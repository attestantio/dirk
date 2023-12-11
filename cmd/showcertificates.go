// Copyright © 2020 Attestant Limited.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/wealdtech/go-majordomo"
)

// ShowCertificates shows information about the certificates configured for Dirk.
func ShowCertificates(ctx context.Context, majordomo majordomo.Service) error {
	certPEMBlock, err := majordomo.Fetch(ctx, viper.GetString("certificates.server-cert"))
	if err != nil {
		return errors.Wrap(err, "failed to obtain server certificate")
	}
	fmt.Fprintf(os.Stdout, "Server certificate obtained from %s\n", viper.GetString("certificates.server-cert"))
	keyPEMBlock, err := majordomo.Fetch(ctx, viper.GetString("certificates.server-key"))
	if err != nil {
		return errors.Wrap(err, "failed to obtain server key")
	}
	fmt.Fprintf(os.Stdout, "Server key obtained from %s\n", viper.GetString("certificates.server-key"))
	var caPEMBlock []byte
	if viper.GetString("certificates.ca-cert") != "" {
		caPEMBlock, err = majordomo.Fetch(ctx, viper.GetString("certificates.ca-cert"))
		if err != nil {
			return errors.Wrap(err, "failed to obtain client CA certificate")
		}
		fmt.Fprintf(os.Stdout, "CA certificate obtained from %s\n", viper.GetString("certificates.ca-cert"))
	}
	fmt.Fprintln(os.Stdout)

	serverCert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return errors.Wrap(err, "invalid server certificate/key")
	}
	if len(serverCert.Certificate) == 0 {
		return errors.New("certificate file does not contain a certificate")
	}
	cert, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil {
		return errors.Wrap(err, "could not read certificate")
	}
	fmt.Fprintf(os.Stdout, "Server certificate issued by: %s\n", cert.Issuer.CommonName)
	if cert.NotAfter.Before(time.Now()) {
		fmt.Fprintf(os.Stdout, "WARNING: server certificate expired at: %v\n", cert.NotAfter)
	} else {
		fmt.Fprintf(os.Stdout, "Server certificate expires: %v\n", cert.NotAfter)
	}
	fmt.Fprintf(os.Stdout, "Server certificate issued to: %s\n", cert.Subject.CommonName)

	for len(caPEMBlock) > 0 {
		var block *pem.Block
		block, caPEMBlock = pem.Decode(caPEMBlock)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		fmt.Fprintf(os.Stdout, "\nCertificate authority certificate is: %s\n", cert.Subject.CommonName)
		if cert.NotAfter.Before(time.Now()) {
			fmt.Fprintf(os.Stdout, "WARNING: certificate authority certificate expired at: %v\n", cert.NotAfter)
		} else {
			fmt.Fprintf(os.Stdout, "Certificate authority certificate expires: %v\n", cert.NotAfter)
		}
	}

	return nil
}
