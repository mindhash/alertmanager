// Copyright 2015 Prometheus Team
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/alertmanager/template"
	"gopkg.in/yaml.v2"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/route"
	"github.com/prometheus/common/version"

	"github.com/prometheus/alertmanager/api/metrics"
	"github.com/prometheus/alertmanager/cluster"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/dispatch"
	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/notify/email"
	"github.com/prometheus/alertmanager/notify/opsgenie"
	"github.com/prometheus/alertmanager/notify/pagerduty"
	"github.com/prometheus/alertmanager/notify/pushover"
	"github.com/prometheus/alertmanager/notify/slack"
	"github.com/prometheus/alertmanager/notify/sns"
	"github.com/prometheus/alertmanager/notify/victorops"
	"github.com/prometheus/alertmanager/notify/webhook"
	"github.com/prometheus/alertmanager/notify/wechat"
	"github.com/prometheus/alertmanager/pkg/labels"
	"github.com/prometheus/alertmanager/provider"
	"github.com/prometheus/alertmanager/silence"
	"github.com/prometheus/alertmanager/silence/silencepb"
	"github.com/prometheus/alertmanager/types"
)

var corsHeaders = map[string]string{
	"Access-Control-Allow-Headers":  "Accept, Authorization, Content-Type, Origin",
	"Access-Control-Allow-Methods":  "GET, POST, DELETE, OPTIONS",
	"Access-Control-Allow-Origin":   "*",
	"Access-Control-Expose-Headers": "Date",
	"Cache-Control":                 "no-cache, no-store, must-revalidate",
}

// Alert is the API representation of an alert, which is a regular alert
// annotated with silencing and inhibition info.
type Alert struct {
	*model.Alert
	Status      types.AlertStatus `json:"status"`
	Receivers   []string          `json:"receivers"`
	Fingerprint string            `json:"fingerprint"`
}

// Enables cross-site script calls.
func setCORS(w http.ResponseWriter) {
	for h, v := range corsHeaders {
		w.Header().Set(h, v)
	}
}

// API provides registration of handlers for API routes.
type API struct {
	alerts   provider.Alerts
	silences *silence.Silences
	config   *config.Config
	route    *dispatch.Route
	uptime   time.Time
	peer     cluster.ClusterPeer
	logger   log.Logger
	m        *metrics.Alerts

	getAlertStatus getAlertStatusFn

	mtx             sync.RWMutex
	template        *template.Template
	dispatch        *dispatch.Dispatcher
	pipelineBuilder *notify.PipelineBuilder
}

func (api *API) SetPipelineBuilder(pipelineBuilder *notify.PipelineBuilder) {
	api.pipelineBuilder = pipelineBuilder
}

func (api *API) SetDispatch(dispatch *dispatch.Dispatcher) {
	api.dispatch = dispatch
}

func (api *API) SetTemplate(template *template.Template) {
	api.template = template
}

type getAlertStatusFn func(model.Fingerprint) types.AlertStatus

// New returns a new API.
func New(
	alerts provider.Alerts,
	silences *silence.Silences,
	sf getAlertStatusFn,
	peer cluster.ClusterPeer,
	l log.Logger,
	r prometheus.Registerer,
) *API {
	if l == nil {
		l = log.NewNopLogger()
	}

	return &API{
		alerts:         alerts,
		silences:       silences,
		getAlertStatus: sf,
		uptime:         time.Now(),
		peer:           peer,
		logger:         l,
		m:              metrics.NewAlerts("v1", r),
	}
}

// Register registers the API handlers under their correct routes
// in the given router.
func (api *API) Register(r *route.Router) {
	wrap := func(f http.HandlerFunc) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			setCORS(w)
			f(w, r)
		})
	}

	r.Options("/*path", wrap(func(w http.ResponseWriter, r *http.Request) {}))

	r.Get("/status", wrap(api.status))
	r.Get("/receivers", wrap(api.receivers))
	r.Del("/receivers/", wrap(api.deleteReceiver))
	r.Post("/receivers", wrap(api.addReceiver))
	r.Put("/receivers/", wrap(api.editReceiver))

	r.Get("/alerts", wrap(api.listAlerts))
	r.Post("/alerts", wrap(api.addAlerts))

	r.Get("/silences", wrap(api.listSilences))
	r.Post("/silences", wrap(api.setSilence))
	r.Get("/silence/:sid", wrap(api.getSilence))
	r.Del("/silence/:sid", wrap(api.delSilence))
}

// Update sets the configuration string to a new value.
func (api *API) Update(cfg *config.Config) {
	api.mtx.Lock()
	defer api.mtx.Unlock()

	api.config = cfg
	api.route = dispatch.NewRoute(cfg.Route, nil)
}

type errorType string

const (
	errorInternal errorType = "server_error"
	errorBadData  errorType = "bad_data"
	errorNotFound errorType = "not_found"
)

type apiError struct {
	typ errorType
	err error
}

func (e *apiError) Error() string {
	return fmt.Sprintf("%s: %s", e.typ, e.err)
}

func (api *API) receivers(w http.ResponseWriter, req *http.Request) {
	api.mtx.RLock()
	defer api.mtx.RUnlock()

	receivers := make([]string, 0, len(api.config.Receivers))
	for _, r := range api.config.Receivers {
		receivers = append(receivers, r.Name)
	}

	api.respond(w, receivers)
}

// buildReceiverIntegrations builds a list of integration notifiers off of a
// receiver config.
func buildReceiverIntegrations(nc *config.Receiver, tmpl *template.Template, logger log.Logger) ([]notify.Integration, error) {
	var (
		errs         types.MultiError
		integrations []notify.Integration
		add          = func(name string, i int, rs notify.ResolvedSender, f func(l log.Logger) (notify.Notifier, error)) {
			n, err := f(log.With(logger, "integration", name))
			if err != nil {
				errs.Add(err)
				return
			}
			integrations = append(integrations, notify.NewIntegration(n, rs, name, i))
		}
	)

	for i, c := range nc.WebhookConfigs {
		add("webhook", i, c, func(l log.Logger) (notify.Notifier, error) { return webhook.New(c, tmpl, l) })
	}
	for i, c := range nc.EmailConfigs {
		add("email", i, c, func(l log.Logger) (notify.Notifier, error) { return email.New(c, tmpl, l), nil })
	}
	for i, c := range nc.PagerdutyConfigs {
		add("pagerduty", i, c, func(l log.Logger) (notify.Notifier, error) { return pagerduty.New(c, tmpl, l) })
	}
	for i, c := range nc.OpsGenieConfigs {
		add("opsgenie", i, c, func(l log.Logger) (notify.Notifier, error) { return opsgenie.New(c, tmpl, l) })
	}
	for i, c := range nc.WechatConfigs {
		add("wechat", i, c, func(l log.Logger) (notify.Notifier, error) { return wechat.New(c, tmpl, l) })
	}
	for i, c := range nc.SlackConfigs {
		add("slack", i, c, func(l log.Logger) (notify.Notifier, error) { return slack.New(c, tmpl, l) })
	}
	for i, c := range nc.VictorOpsConfigs {
		add("victorops", i, c, func(l log.Logger) (notify.Notifier, error) { return victorops.New(c, tmpl, l) })
	}
	for i, c := range nc.PushoverConfigs {
		add("pushover", i, c, func(l log.Logger) (notify.Notifier, error) { return pushover.New(c, tmpl, l) })
	}
	for i, c := range nc.SNSConfigs {
		add("sns", i, c, func(l log.Logger) (notify.Notifier, error) { return sns.New(c, tmpl, l) })
	}
	if errs.Len() > 0 {
		return nil, &errs
	}
	return integrations, nil
}

func (api *API) checkReceiverConfig(receiver *config.Receiver) *apiError {
	var err error
	for _, wh := range receiver.WebhookConfigs {
		if wh.HTTPConfig == nil {
			wh.HTTPConfig = api.config.Global.HTTPConfig
		}
	}
	for _, ec := range receiver.EmailConfigs {
		if ec.Smarthost.String() == "" {
			if api.config.Global.SMTPSmarthost.String() == "" {
				err = fmt.Errorf("no global SMTP smarthost set")
			}
			ec.Smarthost = api.config.Global.SMTPSmarthost
		}
		if ec.From == "" {
			if api.config.Global.SMTPFrom == "" {
				err = fmt.Errorf("no global SMTP from set")
			}
			ec.From = api.config.Global.SMTPFrom
		}
		if ec.Hello == "" {
			ec.Hello = api.config.Global.SMTPHello
		}
		if ec.AuthUsername == "" {
			ec.AuthUsername = api.config.Global.SMTPAuthUsername
		}
		if ec.AuthPassword == "" {
			ec.AuthPassword = api.config.Global.SMTPAuthPassword
		}
		if ec.AuthSecret == "" {
			ec.AuthSecret = api.config.Global.SMTPAuthSecret
		}
		if ec.AuthIdentity == "" {
			ec.AuthIdentity = api.config.Global.SMTPAuthIdentity
		}
		if ec.RequireTLS == nil {
			ec.RequireTLS = new(bool)
			*ec.RequireTLS = api.config.Global.SMTPRequireTLS
		}
	}
	for _, sc := range receiver.SlackConfigs {
		if sc.HTTPConfig == nil {
			sc.HTTPConfig = api.config.Global.HTTPConfig
		}
		if sc.APIURL == nil && len(sc.APIURLFile) == 0 {
			if api.config.Global.SlackAPIURL == nil && len(api.config.Global.SlackAPIURLFile) == 0 {
				err = fmt.Errorf("no global Slack API URL set either inline or in a file")
			}
			sc.APIURL = api.config.Global.SlackAPIURL
			sc.APIURLFile = api.config.Global.SlackAPIURLFile
		}
	}
	for _, poc := range receiver.PushoverConfigs {
		if poc.HTTPConfig == nil {
			poc.HTTPConfig = api.config.Global.HTTPConfig
		}
	}
	for _, pdc := range receiver.PagerdutyConfigs {
		if pdc.HTTPConfig == nil {
			pdc.HTTPConfig = api.config.Global.HTTPConfig
		}
		if pdc.URL == nil {
			if api.config.Global.PagerdutyURL == nil {
				err = fmt.Errorf("no global PagerDuty URL set")
			}
			pdc.URL = api.config.Global.PagerdutyURL
		}
	}
	for _, ogc := range receiver.OpsGenieConfigs {
		if ogc.HTTPConfig == nil {
			ogc.HTTPConfig = api.config.Global.HTTPConfig
		}
		if ogc.APIURL == nil {
			if api.config.Global.OpsGenieAPIURL == nil {
				err = fmt.Errorf("no global OpsGenie URL set")
			}
			ogc.APIURL = api.config.Global.OpsGenieAPIURL
		}
		if !strings.HasSuffix(ogc.APIURL.Path, "/") {
			ogc.APIURL.Path += "/"
		}
		if ogc.APIKey == "" && len(ogc.APIKeyFile) == 0 {
			if api.config.Global.OpsGenieAPIKey == "" && len(api.config.Global.OpsGenieAPIKeyFile) == 0 {
				err = fmt.Errorf("no global OpsGenie API Key set either inline or in a file")
			}
			ogc.APIKey = api.config.Global.OpsGenieAPIKey
			ogc.APIKeyFile = api.config.Global.OpsGenieAPIKeyFile
		}
	}
	for _, wcc := range receiver.WechatConfigs {
		if wcc.HTTPConfig == nil {
			wcc.HTTPConfig = api.config.Global.HTTPConfig
		}

		if wcc.APIURL == nil {
			if api.config.Global.WeChatAPIURL == nil {
				err = fmt.Errorf("no global Wechat URL set")
			}
			wcc.APIURL = api.config.Global.WeChatAPIURL
		}

		if wcc.APISecret == "" {
			if api.config.Global.WeChatAPISecret == "" {
				err = fmt.Errorf("no global Wechat ApiSecret set")
			}
			wcc.APISecret = api.config.Global.WeChatAPISecret
		}

		if wcc.CorpID == "" {
			if api.config.Global.WeChatAPICorpID == "" {
				err = fmt.Errorf("no global Wechat CorpID set")
			}
			wcc.CorpID = api.config.Global.WeChatAPICorpID
		}

		if !strings.HasSuffix(wcc.APIURL.Path, "/") {
			wcc.APIURL.Path += "/"
		}
	}
	for _, voc := range receiver.VictorOpsConfigs {
		if voc.HTTPConfig == nil {
			voc.HTTPConfig = api.config.Global.HTTPConfig
		}
		if voc.APIURL == nil {
			if api.config.Global.VictorOpsAPIURL == nil {
				err = fmt.Errorf("no global VictorOps URL set")
			}
			voc.APIURL = api.config.Global.VictorOpsAPIURL
		}
		if !strings.HasSuffix(voc.APIURL.Path, "/") {
			voc.APIURL.Path += "/"
		}
		if voc.APIKey == "" {
			if api.config.Global.VictorOpsAPIKey == "" {
				err = fmt.Errorf("no global VictorOps API Key set")
			}
			voc.APIKey = api.config.Global.VictorOpsAPIKey
		}
	}
	for _, sns := range receiver.SNSConfigs {
		if sns.HTTPConfig == nil {
			sns.HTTPConfig = api.config.Global.HTTPConfig
		}
	}
	if err != nil {
		return &apiError{err: err, typ: errorBadData}
	}
	return nil
}

func (api *API) setDefaultReceiverForRoute(receiver string) {
	api.config.Route.Receiver = receiver

}

func (api *API) setGlobalSlackURL(slackURL string) *apiError {
	u, err := url.Parse(slackURL)
	if err != nil {
		return &apiError{err: err, typ: errorBadData}
	}
	api.config.Global.SlackAPIURL = &config.SecretURL{URL: u}
	return nil
}

func (api *API) deleteReceiver(w http.ResponseWriter, req *http.Request) {
	api.mtx.RLock()
	defer api.mtx.RUnlock()

	decoder := json.NewDecoder(req.Body)

	var postData map[string]string
	err := decoder.Decode(&postData)

	if err != nil {
		api.respondError(w, apiError{typ: errorBadData, err: err}, nil)
		return
	}
	receiverName := postData["name"]

	_, ok := api.pipelineBuilder.RoutingStage[receiverName]
	if !ok {
		apiErrorObj := apiError{typ: errorNotFound, err: fmt.Errorf("no receiver found with name %s", receiverName)}
		api.respondError(w, apiErrorObj, nil)
		return
	}

	api.dispatch.Stop()

	api.pipelineBuilder.DeleteReceiver(receiverName)

	api.dispatch.SetStage(api.pipelineBuilder.RoutingStage)

	go api.dispatch.Run()

	api.respond(w, "receiver deleted successfully")

}

func (api *API) editReceiver(w http.ResponseWriter, req *http.Request) {
	api.mtx.RLock()
	defer api.mtx.RUnlock()

	decoder := json.NewDecoder(req.Body)

	var postData map[string]string
	err := decoder.Decode(&postData)

	if err != nil {
		api.respondError(w, apiError{typ: errorBadData, err: err}, nil)
		return
	}
	receiverString := postData["data"]

	receiver := &config.Receiver{}

	err = yaml.UnmarshalStrict([]byte(receiverString), receiver)
	if err != nil {
		api.respondError(w, apiError{err: err, typ: errorBadData}, "error in parsing receiver config")
		return
	}

	_, ok := api.pipelineBuilder.RoutingStage[receiver.Name]
	if !ok {
		apiErrorObj := apiError{typ: errorNotFound, err: fmt.Errorf("no receiver found with name %s", receiver.Name)}
		api.respondError(w, apiErrorObj, nil)
		return
	}

	apiErrObj := api.checkReceiverConfig(receiver)
	if apiErrObj != nil {
		api.respondError(w, *apiErrObj, nil)
		return
	}

	api.dispatch.Stop()

	integration, err := buildReceiverIntegrations(receiver, api.template, api.logger)
	if err != nil {
		api.respondError(w, apiError{err: err, typ: errorInternal}, fmt.Sprintf("Error in building receiver integration for receiver: %s", receiver.Name))
		return
	}

	receivers := make(map[string][]notify.Integration, 1)
	receivers[receiver.Name] = integration

	api.pipelineBuilder.DeleteReceiver(receiver.Name)
	api.pipelineBuilder.AddReceivers(receivers)

	api.dispatch.SetStage(api.pipelineBuilder.RoutingStage)

	go api.dispatch.Run()

	api.respond(w, receiver)

}

func (api *API) addReceiver(w http.ResponseWriter, req *http.Request) {
	api.mtx.RLock()
	defer api.mtx.RUnlock()

	// decoder := json.NewDecoder(req.Body)

	// var postData map[string]string
	// err := decoder.Decode(&postData)

	// if err != nil {
	// 	api.respondError(w, apiError{typ: errorBadData, err: err}, nil)
	// 	return
	// }
	// receiverString := postData["data"]

	// receiver := &config.Receiver{}

	// err = yaml.UnmarshalStrict([]byte(receiverString), receiver)
	// if err != nil {
	// 	api.respondError(w, apiError{err: err, typ: errorBadData}, "error in parsing receiver config")
	// 	return
	// }

	defer req.Body.Close()
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {

		api.respondError(w, apiError{typ: errorBadData, err: err}, nil)
		return
	}

	receiver := &config.Receiver{}
	if err := json.Unmarshal(body, receiver); err != nil { // Parse []byte to go struct pointer

		api.respondError(w, apiError{typ: errorBadData, err: err}, nil)
		return
	}
	apiErrObj := api.checkReceiverConfig(receiver)
	if apiErrObj != nil {
		api.respondError(w, *apiErrObj, nil)
		return
	}

	// Adding default receiver for route
	// if api.config.Route == nil {
	api.setDefaultReceiverForRoute(receiver.Name)
	// }
	routes := dispatch.NewRoute(api.config.Route, nil)
	api.dispatch.SetRoute(routes)

	if _, ok := api.pipelineBuilder.RoutingStage[receiver.Name]; ok {
		api.respondError(w, apiError{err: fmt.Errorf("notification config name %s is not unique", receiver.Name), typ: errorBadData}, nil)
		return
	}

	api.dispatch.Stop()

	integration, err := buildReceiverIntegrations(receiver, api.template, api.logger)
	if err != nil {
		api.respondError(w, apiError{err: err, typ: errorInternal}, fmt.Sprintf("Error in building receiver integration for receiver: %s", receiver.Name))
		return
	}

	receivers := make(map[string][]notify.Integration, 1)
	receivers[receiver.Name] = integration
	api.pipelineBuilder.AddReceivers(receivers)

	api.dispatch.SetStage(api.pipelineBuilder.RoutingStage)

	go api.dispatch.Run()

	api.respond(w, receiver)
}

func (api *API) status(w http.ResponseWriter, req *http.Request) {
	api.mtx.RLock()

	var status = struct {
		ConfigYAML    string            `json:"configYAML"`
		ConfigJSON    *config.Config    `json:"configJSON"`
		VersionInfo   map[string]string `json:"versionInfo"`
		Uptime        time.Time         `json:"uptime"`
		ClusterStatus *clusterStatus    `json:"clusterStatus"`
	}{
		ConfigYAML: api.config.String(),
		ConfigJSON: api.config,
		VersionInfo: map[string]string{
			"version":   version.Version,
			"revision":  version.Revision,
			"branch":    version.Branch,
			"buildUser": version.BuildUser,
			"buildDate": version.BuildDate,
			"goVersion": version.GoVersion,
		},
		Uptime:        api.uptime,
		ClusterStatus: getClusterStatus(api.peer),
	}

	api.mtx.RUnlock()

	api.respond(w, status)
}

type peerStatus struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

type clusterStatus struct {
	Name   string       `json:"name"`
	Status string       `json:"status"`
	Peers  []peerStatus `json:"peers"`
}

func getClusterStatus(p cluster.ClusterPeer) *clusterStatus {
	if p == nil {
		return nil
	}
	s := &clusterStatus{Name: p.Name(), Status: p.Status()}

	for _, n := range p.Peers() {
		s.Peers = append(s.Peers, peerStatus{
			Name:    n.Name(),
			Address: n.Address(),
		})
	}
	return s
}

func (api *API) listAlerts(w http.ResponseWriter, r *http.Request) {
	var (
		err            error
		receiverFilter *regexp.Regexp
		// Initialize result slice to prevent api returning `null` when there
		// are no alerts present
		res      = []*Alert{}
		matchers = []*labels.Matcher{}
		ctx      = r.Context()

		showActive, showInhibited     bool
		showSilenced, showUnprocessed bool
	)

	getBoolParam := func(name string) (bool, error) {
		v := r.FormValue(name)
		if v == "" {
			return true, nil
		}
		if v == "false" {
			return false, nil
		}
		if v != "true" {
			err := fmt.Errorf("parameter %q can either be 'true' or 'false', not %q", name, v)
			api.respondError(w, apiError{
				typ: errorBadData,
				err: err,
			}, nil)
			return false, err
		}
		return true, nil
	}

	if filter := r.FormValue("filter"); filter != "" {
		matchers, err = labels.ParseMatchers(filter)
		if err != nil {
			api.respondError(w, apiError{
				typ: errorBadData,
				err: err,
			}, nil)
			return
		}
	}

	showActive, err = getBoolParam("active")
	if err != nil {
		return
	}

	showSilenced, err = getBoolParam("silenced")
	if err != nil {
		return
	}

	showInhibited, err = getBoolParam("inhibited")
	if err != nil {
		return
	}

	showUnprocessed, err = getBoolParam("unprocessed")
	if err != nil {
		return
	}

	if receiverParam := r.FormValue("receiver"); receiverParam != "" {
		receiverFilter, err = regexp.Compile("^(?:" + receiverParam + ")$")
		if err != nil {
			api.respondError(w, apiError{
				typ: errorBadData,
				err: fmt.Errorf(
					"failed to parse receiver param: %s",
					receiverParam,
				),
			}, nil)
			return
		}
	}

	alerts := api.alerts.GetPending()
	defer alerts.Close()

	api.mtx.RLock()
	for a := range alerts.Next() {
		if err = alerts.Err(); err != nil {
			break
		}
		if err = ctx.Err(); err != nil {
			break
		}

		routes := api.route.Match(a.Labels)
		receivers := make([]string, 0, len(routes))
		for _, r := range routes {
			receivers = append(receivers, r.RouteOpts.Receiver)
		}

		if receiverFilter != nil && !receiversMatchFilter(receivers, receiverFilter) {
			continue
		}

		if !alertMatchesFilterLabels(&a.Alert, matchers) {
			continue
		}

		// Continue if the alert is resolved.
		if !a.Alert.EndsAt.IsZero() && a.Alert.EndsAt.Before(time.Now()) {
			continue
		}

		status := api.getAlertStatus(a.Fingerprint())

		if !showActive && status.State == types.AlertStateActive {
			continue
		}

		if !showUnprocessed && status.State == types.AlertStateUnprocessed {
			continue
		}

		if !showSilenced && len(status.SilencedBy) != 0 {
			continue
		}

		if !showInhibited && len(status.InhibitedBy) != 0 {
			continue
		}

		alert := &Alert{
			Alert:       &a.Alert,
			Status:      status,
			Receivers:   receivers,
			Fingerprint: a.Fingerprint().String(),
		}

		res = append(res, alert)
	}
	api.mtx.RUnlock()

	if err != nil {
		api.respondError(w, apiError{
			typ: errorInternal,
			err: err,
		}, nil)
		return
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].Fingerprint < res[j].Fingerprint
	})
	api.respond(w, res)
}

func receiversMatchFilter(receivers []string, filter *regexp.Regexp) bool {
	for _, r := range receivers {
		if filter.MatchString(r) {
			return true
		}
	}

	return false
}

func alertMatchesFilterLabels(a *model.Alert, matchers []*labels.Matcher) bool {
	sms := make(map[string]string)
	for name, value := range a.Labels {
		sms[string(name)] = string(value)
	}
	return matchFilterLabels(matchers, sms)
}

func (api *API) addAlerts(w http.ResponseWriter, r *http.Request) {
	var alerts []*types.Alert
	if err := api.receive(r, &alerts); err != nil {
		api.respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}

	api.insertAlerts(w, r, alerts...)
}

func (api *API) insertAlerts(w http.ResponseWriter, r *http.Request, alerts ...*types.Alert) {
	now := time.Now()

	api.mtx.RLock()
	resolveTimeout := time.Duration(api.config.Global.ResolveTimeout)
	api.mtx.RUnlock()

	for _, alert := range alerts {
		alert.UpdatedAt = now

		// Ensure StartsAt is set.
		if alert.StartsAt.IsZero() {
			if alert.EndsAt.IsZero() {
				alert.StartsAt = now
			} else {
				alert.StartsAt = alert.EndsAt
			}
		}
		// If no end time is defined, set a timeout after which an alert
		// is marked resolved if it is not updated.
		if alert.EndsAt.IsZero() {
			alert.Timeout = true
			alert.EndsAt = now.Add(resolveTimeout)
		}
		if alert.EndsAt.After(time.Now()) {
			api.m.Firing().Inc()
		} else {
			api.m.Resolved().Inc()
		}
	}

	// Make a best effort to insert all alerts that are valid.
	var (
		validAlerts    = make([]*types.Alert, 0, len(alerts))
		validationErrs = &types.MultiError{}
	)
	for _, a := range alerts {
		removeEmptyLabels(a.Labels)

		if err := a.Validate(); err != nil {
			validationErrs.Add(err)
			api.m.Invalid().Inc()
			continue
		}
		validAlerts = append(validAlerts, a)
	}
	if err := api.alerts.Put(validAlerts...); err != nil {
		api.respondError(w, apiError{
			typ: errorInternal,
			err: err,
		}, nil)
		return
	}

	if validationErrs.Len() > 0 {
		api.respondError(w, apiError{
			typ: errorBadData,
			err: validationErrs,
		}, nil)
		return
	}

	api.respond(w, nil)
}

func removeEmptyLabels(ls model.LabelSet) {
	for k, v := range ls {
		if string(v) == "" {
			delete(ls, k)
		}
	}
}

func (api *API) setSilence(w http.ResponseWriter, r *http.Request) {
	var sil types.Silence
	if err := api.receive(r, &sil); err != nil {
		api.respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}

	// This is an API only validation, it cannot be done internally
	// because the expired silence is semantically important.
	// But one should not be able to create expired silences, that
	// won't have any use.
	if sil.Expired() {
		api.respondError(w, apiError{
			typ: errorBadData,
			err: errors.New("start time must not be equal to end time"),
		}, nil)
		return
	}

	if sil.EndsAt.Before(time.Now()) {
		api.respondError(w, apiError{
			typ: errorBadData,
			err: errors.New("end time can't be in the past"),
		}, nil)
		return
	}

	psil, err := silenceToProto(&sil)
	if err != nil {
		api.respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}

	sid, err := api.silences.Set(psil)
	if err != nil {
		api.respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}

	api.respond(w, struct {
		SilenceID string `json:"silenceId"`
	}{
		SilenceID: sid,
	})
}

func (api *API) getSilence(w http.ResponseWriter, r *http.Request) {
	sid := route.Param(r.Context(), "sid")

	sils, _, err := api.silences.Query(silence.QIDs(sid))
	if err != nil || len(sils) == 0 {
		http.Error(w, fmt.Sprint("Error getting silence: ", err), http.StatusNotFound)
		return
	}
	sil, err := silenceFromProto(sils[0])
	if err != nil {
		api.respondError(w, apiError{
			typ: errorInternal,
			err: err,
		}, nil)
		return
	}

	api.respond(w, sil)
}

func (api *API) delSilence(w http.ResponseWriter, r *http.Request) {
	sid := route.Param(r.Context(), "sid")

	if err := api.silences.Expire(sid); err != nil {
		api.respondError(w, apiError{
			typ: errorBadData,
			err: err,
		}, nil)
		return
	}
	api.respond(w, nil)
}

func (api *API) listSilences(w http.ResponseWriter, r *http.Request) {
	psils, _, err := api.silences.Query()
	if err != nil {
		api.respondError(w, apiError{
			typ: errorInternal,
			err: err,
		}, nil)
		return
	}

	matchers := []*labels.Matcher{}
	if filter := r.FormValue("filter"); filter != "" {
		matchers, err = labels.ParseMatchers(filter)
		if err != nil {
			api.respondError(w, apiError{
				typ: errorBadData,
				err: err,
			}, nil)
			return
		}
	}

	sils := []*types.Silence{}
	for _, ps := range psils {
		s, err := silenceFromProto(ps)
		if err != nil {
			api.respondError(w, apiError{
				typ: errorInternal,
				err: err,
			}, nil)
			return
		}

		if !silenceMatchesFilterLabels(s, matchers) {
			continue
		}
		sils = append(sils, s)
	}

	var active, pending, expired []*types.Silence

	for _, s := range sils {
		switch s.Status.State {
		case types.SilenceStateActive:
			active = append(active, s)
		case types.SilenceStatePending:
			pending = append(pending, s)
		case types.SilenceStateExpired:
			expired = append(expired, s)
		}
	}

	sort.Slice(active, func(i int, j int) bool {
		return active[i].EndsAt.Before(active[j].EndsAt)
	})
	sort.Slice(pending, func(i int, j int) bool {
		return pending[i].StartsAt.Before(pending[j].EndsAt)
	})
	sort.Slice(expired, func(i int, j int) bool {
		return expired[i].EndsAt.After(expired[j].EndsAt)
	})

	// Initialize silences explicitly to an empty list (instead of nil)
	// So that it does not get converted to "null" in JSON.
	silences := []*types.Silence{}
	silences = append(silences, active...)
	silences = append(silences, pending...)
	silences = append(silences, expired...)

	api.respond(w, silences)
}

func silenceMatchesFilterLabels(s *types.Silence, matchers []*labels.Matcher) bool {
	sms := make(map[string]string)
	for _, m := range s.Matchers {
		sms[m.Name] = m.Value
	}

	return matchFilterLabels(matchers, sms)
}

func matchFilterLabels(matchers []*labels.Matcher, sms map[string]string) bool {
	for _, m := range matchers {
		v, prs := sms[m.Name]
		switch m.Type {
		case labels.MatchNotRegexp, labels.MatchNotEqual:
			if string(m.Value) == "" && prs {
				continue
			}
			if !m.Matches(string(v)) {
				return false
			}
		default:
			if string(m.Value) == "" && !prs {
				continue
			}
			if !m.Matches(string(v)) {
				return false
			}
		}
	}

	return true
}

func silenceToProto(s *types.Silence) (*silencepb.Silence, error) {
	sil := &silencepb.Silence{
		Id:        s.ID,
		StartsAt:  s.StartsAt,
		EndsAt:    s.EndsAt,
		UpdatedAt: s.UpdatedAt,
		Comment:   s.Comment,
		CreatedBy: s.CreatedBy,
	}
	for _, m := range s.Matchers {
		matcher := &silencepb.Matcher{
			Name:    m.Name,
			Pattern: m.Value,
		}
		switch m.Type {
		case labels.MatchEqual:
			matcher.Type = silencepb.Matcher_EQUAL
		case labels.MatchNotEqual:
			matcher.Type = silencepb.Matcher_NOT_EQUAL
		case labels.MatchRegexp:
			matcher.Type = silencepb.Matcher_REGEXP
		case labels.MatchNotRegexp:
			matcher.Type = silencepb.Matcher_NOT_REGEXP
		}
		sil.Matchers = append(sil.Matchers, matcher)
	}
	return sil, nil
}

func silenceFromProto(s *silencepb.Silence) (*types.Silence, error) {
	sil := &types.Silence{
		ID:        s.Id,
		StartsAt:  s.StartsAt,
		EndsAt:    s.EndsAt,
		UpdatedAt: s.UpdatedAt,
		Status: types.SilenceStatus{
			State: types.CalcSilenceState(s.StartsAt, s.EndsAt),
		},
		Comment:   s.Comment,
		CreatedBy: s.CreatedBy,
	}
	for _, m := range s.Matchers {
		var t labels.MatchType
		switch m.Type {
		case silencepb.Matcher_EQUAL:
			t = labels.MatchEqual
		case silencepb.Matcher_NOT_EQUAL:
			t = labels.MatchNotEqual
		case silencepb.Matcher_REGEXP:
			t = labels.MatchRegexp
		case silencepb.Matcher_NOT_REGEXP:
			t = labels.MatchNotRegexp
		}
		matcher, err := labels.NewMatcher(t, m.Name, m.Pattern)
		if err != nil {
			return nil, err
		}

		sil.Matchers = append(sil.Matchers, matcher)
	}

	return sil, nil
}

type status string

const (
	statusSuccess status = "success"
	statusError   status = "error"
)

type response struct {
	Status    status      `json:"status"`
	Data      interface{} `json:"data,omitempty"`
	ErrorType errorType   `json:"errorType,omitempty"`
	Error     string      `json:"error,omitempty"`
}

func (api *API) respond(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	b, err := json.Marshal(&response{
		Status: statusSuccess,
		Data:   data,
	})
	if err != nil {
		level.Error(api.logger).Log("msg", "Error marshaling JSON", "err", err)
		return
	}

	if _, err := w.Write(b); err != nil {
		level.Error(api.logger).Log("msg", "failed to write data to connection", "err", err)
	}
}

func (api *API) respondError(w http.ResponseWriter, apiErr apiError, data interface{}) {
	w.Header().Set("Content-Type", "application/json")

	switch apiErr.typ {
	case errorBadData:
		w.WriteHeader(http.StatusBadRequest)
	case errorInternal:
		w.WriteHeader(http.StatusInternalServerError)
	case errorNotFound:
		w.WriteHeader(http.StatusNotFound)
	default:
		panic(fmt.Sprintf("unknown error type %q", apiErr.Error()))
	}

	b, err := json.Marshal(&response{
		Status:    statusError,
		ErrorType: apiErr.typ,
		Error:     apiErr.err.Error(),
		Data:      data,
	})
	if err != nil {
		return
	}
	level.Error(api.logger).Log("msg", "API error", "err", apiErr.Error())

	if _, err := w.Write(b); err != nil {
		level.Error(api.logger).Log("msg", "failed to write data to connection", "err", err)
	}
}

func (api *API) receive(r *http.Request, v interface{}) error {
	dec := json.NewDecoder(r.Body)
	defer r.Body.Close()

	err := dec.Decode(v)
	if err != nil {
		level.Debug(api.logger).Log("msg", "Decoding request failed", "err", err)
		return err
	}
	return nil
}
