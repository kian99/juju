// Copyright 2020 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package caasadmission

import (
	"bytes"
	"fmt"

	"github.com/juju/errors"
	admission "k8s.io/api/admissionregistration/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	k8sconstants "github.com/juju/juju/caas/kubernetes/provider/constants"
	k8sutils "github.com/juju/juju/caas/kubernetes/provider/utils"
	"github.com/juju/juju/pki"
)

// AdmissionCreator represents a creator of mutating webhooks that is context aware of the
// current controller.
type AdmissionCreator interface {
	EnsureMutatingWebhookConfiguration() (func(), error)
}

// AdmissionCreatorFunc is the func type of AdmissionCreator.
type AdmissionCreatorFunc func() (func(), error)

const (
	// Component describes a sub zone to use on the juju tld for unique resource
	// ids. For example using this component "admission" with "juju.io" would
	// yield admission.juju.io
	Component = "admission"
)

var (
	anyMatch = []string{"*"}
)

// EnsureMutatingWebhookConfiguration implements AdmissionCreator interface for
// func type.
func (a AdmissionCreatorFunc) EnsureMutatingWebhookConfiguration() (func(), error) {
	return a()
}

// NewAdmissionCreator instantiates a new AdmissionCreator for the supplied
// context arguments.
func NewAdmissionCreator(
	authority pki.Authority,
	namespace, modelName string,
	legacyLabels bool,
	ensureConfig func(*admission.MutatingWebhookConfiguration) (func(), error),
	service *admission.ServiceReference) (AdmissionCreator, error) {

	caPemBuffer := bytes.Buffer{}
	if err := pki.CertificateToPemWriter(&caPemBuffer, map[string]string{},
		authority.Certificate()); err != nil {
		return nil, errors.Trace(err)
	}

	// TODO change to fail
	failurePolicy := admission.Ignore
	matchPolicy := admission.Equivalent
	ruleScope := admission.AllScopes
	sideEffects := admission.SideEffectClassNone

	// MutatingWebhook Obj
	obj := admission.MutatingWebhookConfiguration{
		ObjectMeta: meta.ObjectMeta{
			Labels:    k8sutils.LabelsForModel(modelName, legacyLabels),
			Name:      fmt.Sprintf("juju-model-admission-%s", namespace),
			Namespace: namespace,
		},
		Webhooks: []admission.MutatingWebhook{
			{
				SideEffects: &sideEffects,
				ClientConfig: admission.WebhookClientConfig{
					CABundle: caPemBuffer.Bytes(),
					Service:  service,
				},
				FailurePolicy: &failurePolicy,
				MatchPolicy:   &matchPolicy,
				Name:          k8sutils.MakeK8sDomain(Component),
				NamespaceSelector: &meta.LabelSelector{
					MatchLabels: k8sutils.LabelsForModel(modelName, legacyLabels),
				},
				ObjectSelector: &meta.LabelSelector{
					MatchExpressions: []meta.LabelSelectorRequirement{
						{
							Key:      k8sconstants.LabelJujuModelOperatorDisableWebhook,
							Operator: meta.LabelSelectorOpDoesNotExist,
						},
					},
				},
				Rules: []admission.RuleWithOperations{
					{
						Operations: []admission.OperationType{
							admission.Create,
							admission.Update,
						},
						Rule: admission.Rule{
							APIGroups:   anyMatch,
							APIVersions: anyMatch,
							Resources:   anyMatch,
							Scope:       &ruleScope,
						},
					},
				},
			},
		},
	}

	return AdmissionCreatorFunc(func() (func(), error) {
		leafGroup := fmt.Sprintf("k8sadmission-%s", modelName)
		_, err := authority.LeafRequestForGroup(leafGroup).
			AddDNSNames(fmt.Sprintf("%s.%s.svc", service.Name, service.Namespace)).
			Commit()
		if err != nil {
			return nil, errors.Trace(err)
		}

		configCleanup, err := ensureConfig(&obj)
		if err != nil {
			return nil, errors.Trace(err)
		}

		return func() {
			configCleanup()
		}, nil
	}), nil
}
