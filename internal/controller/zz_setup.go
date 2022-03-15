/*
Copyright 2021 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/crossplane/terrajet/pkg/controller"

	application "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/access/application"
	cacertificate "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/access/cacertificate"
	group "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/access/group"
	identityprovider "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/access/identityprovider"
	keysconfiguration "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/access/keysconfiguration"
	mutualtlscertificate "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/access/mutualtlscertificate"
	policy "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/access/policy"
	rule "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/access/rule"
	servicetoken "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/access/servicetoken"
	member "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/account/member"
	token "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/api/token"
	tunnel "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/argo/tunnel"
	originpulls "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/authenticated/originpulls"
	originpullscertificate "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/authenticated/originpullscertificate"
	ipprefix "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/byo/ipprefix"
	pack "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/certificate/pack"
	argo "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/cloudflare/argo"
	filter "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/cloudflare/filter"
	healthcheck "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/cloudflare/healthcheck"
	record "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/cloudflare/record"
	ruleset "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/cloudflare/ruleset"
	zone "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/cloudflare/zone"
	hostname "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/custom/hostname"
	hostnamefallbackorigin "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/custom/hostnamefallbackorigin"
	pages "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/custom/pages"
	ssl "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/custom/ssl"
	policycertificates "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/device/policycertificates"
	postureintegration "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/device/postureintegration"
	posturerule "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/device/posturerule"
	domain "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/fallback/domain"
	rulefirewall "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/firewall/rule"
	tunnelgre "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/gre/tunnel"
	list "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/ip/list"
	tunnelipsec "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/ipsec/tunnel"
	balancer "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/load/balancer"
	balancermonitor "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/load/balancermonitor"
	balancerpool "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/load/balancerpool"
	retention "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/logpull/retention"
	job "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/logpush/job"
	ownershipchallenge "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/logpush/ownershipchallenge"
	policywebhooks "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/notification/policywebhooks"
	cacertificateorigin "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/origin/cacertificate"
	rulepage "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/page/rule"
	providerconfig "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/providerconfig"
	applicationspectrum "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/spectrum/application"
	tunnelsplit "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/split/tunnel"
	route "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/static/route"
	account "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/teams/account"
	listteams "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/teams/list"
	location "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/teams/location"
	ruleteams "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/teams/rule"
	groupwaf "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/waf/group"
	override "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/waf/override"
	rulewaf "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/waf/rule"
	room "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/waiting/room"
	crontrigger "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/worker/crontrigger"
	routeworker "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/worker/route"
	script "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/worker/script"
	kv "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/workers/kv"
	kvnamespace "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/workers/kvnamespace"
	cachevariants "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/zone/cachevariants"
	dnssec "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/zone/dnssec"
	lockdown "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/zone/lockdown"
	settingsoverride "github.com/davidcollom/crossplane-jet-cloudflare/internal/controller/zone/settingsoverride"
)

// Setup creates all controllers with the supplied logger and adds them to
// the supplied manager.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	for _, setup := range []func(ctrl.Manager, controller.Options) error{
		application.Setup,
		cacertificate.Setup,
		group.Setup,
		identityprovider.Setup,
		keysconfiguration.Setup,
		mutualtlscertificate.Setup,
		policy.Setup,
		rule.Setup,
		servicetoken.Setup,
		member.Setup,
		token.Setup,
		tunnel.Setup,
		originpulls.Setup,
		originpullscertificate.Setup,
		ipprefix.Setup,
		pack.Setup,
		argo.Setup,
		filter.Setup,
		healthcheck.Setup,
		record.Setup,
		ruleset.Setup,
		zone.Setup,
		hostname.Setup,
		hostnamefallbackorigin.Setup,
		pages.Setup,
		ssl.Setup,
		policycertificates.Setup,
		postureintegration.Setup,
		posturerule.Setup,
		domain.Setup,
		rulefirewall.Setup,
		tunnelgre.Setup,
		list.Setup,
		tunnelipsec.Setup,
		balancer.Setup,
		balancermonitor.Setup,
		balancerpool.Setup,
		retention.Setup,
		job.Setup,
		ownershipchallenge.Setup,
		policywebhooks.Setup,
		cacertificateorigin.Setup,
		rulepage.Setup,
		providerconfig.Setup,
		applicationspectrum.Setup,
		tunnelsplit.Setup,
		route.Setup,
		account.Setup,
		listteams.Setup,
		location.Setup,
		ruleteams.Setup,
		groupwaf.Setup,
		override.Setup,
		rulewaf.Setup,
		room.Setup,
		crontrigger.Setup,
		routeworker.Setup,
		script.Setup,
		kv.Setup,
		kvnamespace.Setup,
		cachevariants.Setup,
		dnssec.Setup,
		lockdown.Setup,
		settingsoverride.Setup,
	} {
		if err := setup(mgr, o); err != nil {
			return err
		}
	}
	return nil
}
