package syncthing

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	rice "github.com/GeertJohan/go.rice"
	"github.com/kelda-inc/blimp/pkg/cfgdir"
)

const Marker = ".kelda_syncthing"

// I don't wnat to use the standard syncthing port, in case one of our users
// wants to run syncthing in docker compose.  It doesn't look like anything
// actually uses this port so we should be good w.r.t. conflicts.  The "right"
// thing to do, would be to use a unix socket in the CLI, and then conflicts
// aren't possible.
const Port = 22022

// XXX:  It's really not good to be hardcoding these certs.  Ideally we would
// use openssl to generate them, but then we would need to send the device id
// (based on the public cert) to the other end of the connection.  Since all
// this is running over https anyways, in the short term this shortcut may be
// fine, but it's not great in general.
var cert string = `-----BEGIN CERTIFICATE-----
MIIBmTCCASCgAwIBAgIIek07ZhbcKB8wCgYIKoZIzj0EAwIwFDESMBAGA1UEAxMJ
c3luY3RoaW5nMB4XDTIwMDMyMjAwMDAwMFoXDTQwMDMxNzAwMDAwMFowFDESMBAG
A1UEAxMJc3luY3RoaW5nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEBtFWxkBr049U
IoXeiZ0ZUXvxEQ0mqIOcp6xkAxd2TriHiYvRdEaxoICxhzkZYQFd8mX/exWgJjii
uPpfnKPxOyKGWlH7bIOqq/DGb5AGf+V4YW+FtS7N64TeWuBH+AmRoz8wPTAOBgNV
HQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1Ud
EwEB/wQCMAAwCgYIKoZIzj0EAwIDZwAwZAIwA35yOlgN3Cj6YId4Ah2VCsYGvvZ5
IWdlUNNANitQDliipjwQn9r++GRYORFr2XzwAjAF8CYhyq2qgbZFo7LRrXF6y97L
g+sYvRpAXK+ToCQcFK0D8MKZ7lPWhgkT6pPqc9c=
-----END CERTIFICATE-----`

var key string = `-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDD8/1oLh8DZYo3G6x/PcUQI45/oECcE3S9zF/UMld+jKGDy2wIE/m5d
Lao59xVD8GOgBwYFK4EEACKhZANiAAQG0VbGQGvTj1Qihd6JnRlRe/ERDSaog5yn
rGQDF3ZOuIeJi9F0RrGggLGHORlhAV3yZf97FaAmOKK4+l+co/E7IoZaUftsg6qr
8MZvkAZ/5Xhhb4W1Ls3rhN5a4Ef4CZE=
-----END EC PRIVATE KEY-----`

func MapToArgs(m map[string]string) []string {
	var args []string
	for id, path := range m {
		args = append(args, id+","+path)
	}
	return args
}

func ArgsToMap(args []string) map[string]string {
	m := map[string]string{}
	for _, arg := range args {
		kv := strings.Split(arg, ",")
		path := kv[1]

		m[kv[0]] = path
	}

	return m
}

func MakeMarkers(folders map[string]string) error {
	for _, path := range folders {
		markerPath := path + "/" + Marker
		err := os.Mkdir(markerPath, 0444)
		if err != nil && !os.IsExist(err) {
			return err
		}
	}

	return nil
}

func MakeServer(folders map[string]string) string {
	return makeConfig(true, folders)
}

func Run(folders map[string]string) error {
	box := rice.MustFindBox("stbin")

	err := MakeMarkers(folders)
	if err != nil {
		return fmt.Errorf("making syncthing markers: %w", err)
	}

	stbinBytes, err := box.Bytes("")
	if err != nil {
		// This really really can't happen as stbin is supposed to be
		// literally embedded in this binary.  A panic is actually
		// appropriate.
		panic(err)
	}

	stbinPath := cfgdir.Expand("stbin")
	err = ioutil.WriteFile(stbinPath, stbinBytes, 0755)
	if err != nil {
		return fmt.Errorf("write stbin error: %w", err)
	}

	fileMap := map[string]string{
		"config.xml": makeConfig(false, folders),
		"cert.pem":   cert,
		"key.pem":    key,
	}

	for path, data := range fileMap {
		err := ioutil.WriteFile(cfgdir.Expand(path), []byte(data), 0666)
		if err != nil {
			return fmt.Errorf("write config file error: %w", err)
		}
	}

	return exec.Command(stbinPath, "-verbose", "-home", cfgdir.Expand(""),
		"-logfile", cfgdir.Expand("syncthing.log")).Run()
}

func makeConfig(server bool, folders map[string]string) string {
	// A folder is a map from folder ID to a path.

	var folderStrs []string
	for id, path := range folders {
		folderStrs = append(folderStrs, makeFolder(id, path))
	}

	var listenAddress, address string
	if server {
		listenAddress = fmt.Sprintf("tcp://0.0.0.0:%d", Port)
	} else {
		address = fmt.Sprintf("tcp://127.0.0.1:%d", Port)
	}

	return fmt.Sprintf(`<configuration version="30">%s
    <gui enabled="false"></gui>
    <device id="K6QHA3P-VGHXBZE-2NILDY3-Y4E2EUU-7DCSOVF-DFVCQRM-P5BVGMB-LDLP6QA" compression="always">
        <address>%s</address>
    </device>
    <device id="ROHA7NN-4KWKQ3Q-CHJMZBK-6UD7Z6D-ZTWQR5C-TYLN6WG-Q2EQJAI-JU73EQN" compression="always"/>
    <options>
        <listenAddress>%s</listenAddress>
        <globalAnnounceEnabled>false</globalAnnounceEnabled>
        <localAnnounceEnabled>false</localAnnounceEnabled>
        <reconnectionIntervalS>10</reconnectionIntervalS>
        <relaysEnabled>false</relaysEnabled>
        <startBrowser>false</startBrowser>
        <natEnabled>false</natEnabled>
        <urAccepted>-1</urAccepted>
        <restartOnWakeup>false</restartOnWakeup>
        <autoUpgradeIntervalH>0</autoUpgradeIntervalH>
        <keepTemporariesH>24</keepTemporariesH>
        <cacheIgnoredFiles>false</cacheIgnoredFiles>
        <overwriteRemoteDeviceNamesOnConnect>false</overwriteRemoteDeviceNamesOnConnect>
        <defaultFolderPath></defaultFolderPath>
        <setLowPriority>false</setLowPriority>
        <crashReportingEnabled>false</crashReportingEnabled>
        <stunServer></stunServer>
    </options>
</configuration>`, strings.Join(folderStrs, ""), address, listenAddress)
}

func makeFolder(id, path string) string {
	return fmt.Sprintf(`
    <folder id="%s" path="%s" type="sendreceive"
        rescanIntervalS="30" fsWatcherEnabled="true" fsWatcherDelayS="1"
        autoNormalize="true">
        <device id="K6QHA3P-VGHXBZE-2NILDY3-Y4E2EUU-7DCSOVF-DFVCQRM-P5BVGMB-LDLP6QA"/>
        <device id="ROHA7NN-4KWKQ3Q-CHJMZBK-6UD7Z6D-ZTWQR5C-TYLN6WG-Q2EQJAI-JU73EQN"/>
        <order>oldestFirst</order>
        <ignoreDelete>false</ignoreDelete>
        <maxConflicts>-1</maxConflicts>
        <markerName>%s</markerName>
    </folder>`, id, path, Marker)
}
