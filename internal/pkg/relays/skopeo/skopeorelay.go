/*
	Copyright 2020 Alexander Vollschwitz <xelalex@gmx.net>

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

package skopeo

import (
	"bytes"
	"fmt"
	"io"

	log "github.com/sirupsen/logrus"

	"github.com/xelalexv/dregsy/internal/pkg/relays"
	"github.com/xelalexv/dregsy/internal/pkg/util"
)

const RelayID = "skopeo"

//
type RelayConfig struct {
	Binary   string `yaml:"binary"`
	CertsDir string `yaml:"certs-dir"`
	Mode     string `yaml:"mode"`
}

//
type Support struct{}

//
func (s *Support) Platform(p string) error {
	return nil
}

//
type SkopeoRelay struct {
	wrOut io.Writer
}

//
func NewSkopeoRelay(conf *RelayConfig, out io.Writer) *SkopeoRelay {

	relay := &SkopeoRelay{}

	if out != nil {
		relay.wrOut = out
	}
	if conf != nil {
		if conf.Binary != "" {
			skopeoBinary = conf.Binary
		}
		if conf.CertsDir != "" {
			certsBaseDir = conf.CertsDir
		}
		if conf.Mode != "" {
			skopeoMode = conf.Mode
		} else {
			skopeoMode = "copy"  // Ensure default mode is "copy"
		}
	}

	return relay
}

//
func (r *SkopeoRelay) Prepare() error {

	bufOut := new(bytes.Buffer)
	if err := runSkopeo(bufOut, nil, true, "--version"); err != nil {
		return fmt.Errorf("cannot execute skopeo: %v", err)
	}

	log.Info(bufOut.String())
	log.WithField("relay", RelayID).Info("relay ready")

	return nil
}

//
func (r *SkopeoRelay) Dispose() error {
	return nil
}

//
func (r *SkopeoRelay) Sync(opt *relays.SyncOptions) error {

    srcCreds := util.DecodeJSONAuth(opt.SrcAuth)
    destCreds := util.DecodeJSONAuth(opt.TrgtAuth)

    // Base command differs based on the skopeoMode
    cmd := []string{"--insecure-policy"}
    if skopeoMode == "sync" {
        cmd = append(cmd, "sync")
    } else { // Default to "copy"
        cmd = append(cmd, "copy")
    }

    if opt.SrcSkipTLSVerify {
        cmd = append(cmd, "--src-tls-verify=false")
    }
    if opt.TrgtSkipTLSVerify {
        cmd = append(cmd, "--dest-tls-verify=false")
    }

    srcCertDir := ""
    reg, _, _ := util.SplitRef(opt.SrcRef)
    if reg != "" {
        srcCertDir = CertsDirForRegistry(reg)
        cmd = append(cmd, fmt.Sprintf("--src-cert-dir=%s", srcCertDir))
    }
    reg, _, _ = util.SplitRef(opt.TrgtRef)
    if reg != "" {
        cmd = append(cmd, fmt.Sprintf("--dest-cert-dir=%s/%s", certsBaseDir, util.WithoutPort(reg)))
    }

    if srcCreds != "" {
        cmd = append(cmd, fmt.Sprintf("--src-creds=%s", srcCreds))
    }
    if destCreds != "" {
        cmd = append(cmd, fmt.Sprintf("--dest-creds=%s", destCreds))
    }

    tags, err := opt.Tags.Expand(func() ([]string, error) {
        return util.ListAllTags(opt.SrcRef, srcCreds, srcCertDir, opt.SrcSkipTLSVerify)
    })

    if err != nil {
        return fmt.Errorf("error expanding tags: %v", err)
    }

    errs := false

    for _, t := range tags {

        log.WithFields(log.Fields{"tag": t, "platform": opt.Platform}).Info("syncing tag")

        src, trgt := util.JoinRefsAndTag(opt.SrcRef, opt.TrgtRef, t)  // Used for both modes now

        rc := append(cmd, fmt.Sprintf("docker://%s", src), fmt.Sprintf("docker://%s", trgt))

        switch opt.Platform {
        case "":
        case "all":
            rc = append(rc, "--all")
        default:
            rc = util.AddPlatformOverrides(rc, opt.Platform)
        }

        if err := util.RunSkopeo(r.wrOut, r.wrOut, opt.Verbose, rc...); err != nil {
            log.Error(err)
            errs = true
        }
    }

    if errs {
        return fmt.Errorf("errors during sync")
    }

    return nil
}
