package node

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/InazumaV/V2bX/common/file"
	log "github.com/sirupsen/logrus"
)

func (c *Controller) renewCertTask() error {
	l, err := NewLego(c.CertConfig)
	if err != nil {
		log.WithField("tag", c.tag).Info("new lego error: ", err)
		return nil
	}
	err = l.RenewCert()
	if err != nil {
		log.WithField("tag", c.tag).Info("renew cert error: ", err)
		return nil
	}
	return nil
}

func (c *Controller) requestCert() error {
	switch c.CertConfig.CertMode {
	case "none", "":
	case "file":
		if c.CertConfig.CertFile == "" || c.CertConfig.KeyFile == "" {
			return fmt.Errorf("cert file path or key file path not exist")
		}
	case "dns", "http":
		if c.CertConfig.CertFile == "" || c.CertConfig.KeyFile == "" {
			return fmt.Errorf("cert file path or key file path not exist")
		}
		if file.IsExist(c.CertConfig.CertFile) && file.IsExist(c.CertConfig.KeyFile) {
			return nil
		}
		l, err := NewLego(c.CertConfig)
		if err != nil {
			return fmt.Errorf("create lego object error: %s", err)
		}
		err = l.CreateCert()
		if err != nil {
			return fmt.Errorf("create lego cert error: %s", err)
		}
	case "self":
		if c.CertConfig.CertFile == "" || c.CertConfig.KeyFile == "" {
			return fmt.Errorf("cert file path or key file path not exist")
		}
		domain := c.CertConfig.CertDomain
		if domain == "" && c.info != nil && c.info.Common != nil {
			domain = c.info.Common.ServerName
			if domain == "" {
				domain = c.info.Common.Host
			}
		}
		if domain == "" {
			domain = "localhost"
		}
		if file.IsExist(c.CertConfig.KeyFile) && selfCertUsable(c.CertConfig.CertFile, domain) {
			return nil
		}
		err := generateSelfSslCertificate(
			domain,
			c.CertConfig.CertFile,
			c.CertConfig.KeyFile)
		if err != nil {
			return fmt.Errorf("generate self cert error: %s", err)
		}
	default:
		return fmt.Errorf("unsupported certmode: %s", c.CertConfig.CertMode)
	}
	return nil
}

// 旧版自签（RSA / 30 年有效期）或快过期、域名不符的证书需要重签
func selfCertUsable(certPath, domain string) bool {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
		return false
	}
	if cert.NotAfter.Sub(cert.NotBefore) > 4*365*24*time.Hour || time.Until(cert.NotAfter) < 30*24*time.Hour {
		return false
	}
	return cert.VerifyHostname(domain) == nil
}

func selfCertOrganization(domain string) string {
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return domain
	}
	name := labels[len(labels)-2]
	if name == "" {
		return domain
	}
	return strings.ToUpper(name[:1]) + name[1:]
}

func generateSelfSslCertificate(domain, certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ecdsa key error: %s", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial error: %s", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal ecdsa key error: %s", err)
	}
	notBefore := time.Now().Add(-time.Duration(mrand.Intn(72)+1) * time.Hour)
	tmpl := &x509.Certificate{
		Version:      3,
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: domain,
		},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(3, 0, 0),
	}
	if ip := net.ParseIP(domain); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.Subject.Organization = []string{selfCertOrganization(domain)}
		tmpl.DNSNames = []string{domain}
		if i := strings.IndexByte(domain, '.'); i > 0 && strings.Count(domain, ".") >= 2 {
			tmpl.DNSNames = append(tmpl.DNSNames, "*"+domain[i:])
		}
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return fmt.Errorf("create cert dir error: %s", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return fmt.Errorf("create key dir error: %s", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	if err = os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write cert file error: %s", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})
	if err = os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write key file error: %s", err)
	}
	return nil
}
