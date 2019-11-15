package main

import (
	"fmt"
	"github.com/vbatts/acme-reverseproxy/proxymap"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"net/http"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"github.com/vbatts/acme-reverseproxy/config"
)

var cfg config.Config

func main() {
	genConfigAction()
	srvCommand()
}

func genConfigAction() error {
	tmpConfig := config.Config{
		CA: config.CA{
			Email:    "admin@kyma-project.io",
			CacheDir: "/tmp/acme-reverseproxy",
		},
		Mapping: map[string]string{
			"acmeproxy.kyma-goat.ga": "http://localhost:9096",
		},
	}
	e := toml.NewEncoder(os.Stdout)
	if err := e.Encode(tmpConfig); err != nil {
		return err
	}
	cfg = tmpConfig
	return nil
}

func srvCommand() error {
	var stagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"
	list := []string{}
	for key := range cfg.Mapping {
		if key != "" {
			list = append(list, key)
		}
	}
	fmt.Println(list)
	rpm, err := proxymap.ToReverseProxyMap(cfg.Mapping)
	if err != nil {
		return cli.NewExitError(err, 2)
	}
	rph := proxymap.NewReverseProxiesHandler(rpm)
	logrus.Debugf("srv: whitelisting %q", strings.Join(list, ","))
	m := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(strings.Join(list, ",")),
		Client:     &acme.Client{DirectoryURL: stagingDirectory},
	}
	if cfg.CA.Email != "" {
		m.Email = cfg.CA.Email
	}
	if cfg.CA.CacheDir != "" {
		m.Cache = autocert.DirCache(cfg.CA.CacheDir)
	}
	//setNewACMEClient(&m)

	listener := m.Listener()
	return http.Serve(listener, rph)
}
