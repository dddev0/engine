// Copyright © by Jeff Foley 2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/asset-db/types"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
)

type knownFQDN struct {
	name string
	log  *slog.Logger
}

func NewKnownFQDN() et.Plugin {
	return &knownFQDN{name: "Known-FQDN"}
}

func (d *knownFQDN) Name() string {
	return d.name
}

func (d *knownFQDN) Start(r et.Registry) error {
	d.log = r.Log().WithGroup("plugin").With("name", d.name)

	name := d.name + "-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     d,
		Name:       name,
		Transforms: []string{"fqdn"},
		EventType:  oam.FQDN,
		Callback:   d.check,
	}); err != nil {
		return err
	}

	d.log.Info("Plugin started")
	return nil
}

func (d *knownFQDN) Stop() {
	d.log.Info("Plugin stopped")
}

func (d *knownFQDN) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if e.Session.Config().WhichDomain(domlt) != domlt {
		return nil
	}

	assets, err := d.query(e, fqdn)
	if err != nil {
		e.Session.Log().Error(fmt.Sprintf("Failed to query the asset database: %v", err),
			slog.Group("plugin", "name", d.name, "handler", d.name+"-Handler"))
		return nil
	}

	d.process(e, assets)
	return nil
}

func (d *knownFQDN) query(e *et.Event, dom *domain.FQDN) ([]*types.Asset, error) {
	return e.Session.DB().FindByScope([]oam.Asset{dom}, time.Time{})
}

func (d *knownFQDN) process(e *et.Event, assets []*types.Asset) {
	for _, a := range assets {
		if fqdn, ok := a.Asset.(*domain.FQDN); ok {
			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    fqdn.Name,
				Asset:   a,
				Session: e.Session,
			})
		}
	}
}
