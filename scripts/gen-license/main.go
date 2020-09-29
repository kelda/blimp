package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/kelda-inc/blimp/pkg/license"
)

func main() {
	var customer string
	var seats int
	var expiryDays int
	var expiryTimeStr string
	var privateKeyPath string
	var outputPath string

	flag.StringVar(&customer, "customer", "", "Company that will be using the license")
	flag.IntVar(&seats, "seats", -1, "Number of seats")
	flag.IntVar(&expiryDays, "expiration-days", -1, "Days until license expires")
	flag.StringVar(&expiryTimeStr, "expiration-date", "", "Datetime that license expires (in RFC3339 format, e.g. 2006-01-02T15:04:05)")
	flag.StringVar(&privateKeyPath, "privkey", "", "Path to private key")
	flag.StringVar(&outputPath, "out", "", "Output path for license")
	flag.Parse()

	if seats == -1 {
		log.Fatal("Please specify -seats")
	}

	expiryTime, err := time.Parse(time.RFC3339, expiryTimeStr)
	if err != nil {
		_, ok := err.(*time.ParseError)
		if !ok {
			log.WithError(err).Fatal("Failed to parse expiration datetime")
		}
		// This is a ParseError, so just use expiryMonths instead.
		if expiryDays == -1 {
			log.Fatal("Please specify -expiration-days or -expiration-date")
		}
		expiryTime = time.Now().Add(time.Duration(expiryDays*24) * time.Hour)
	}
	expiryTime = expiryTime.UTC()

	if privateKeyPath == "" {
		log.Fatal("Please specify -privkey")
	}

	if outputPath == "" {
		log.Fatal("Please specify -out")
	}

	privKeyBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		log.WithError(err).WithField("privateKeyPath", privateKeyPath).
			Fatal("Failed to read private key")
	}

	privKey := ed25519.PrivateKey(privKeyBytes)

	rawLicense := license.License{
		Customer:   customer,
		Seats:      seats,
		ExpiryTime: expiryTime,
	}
	licenseBytes, err := json.Marshal(rawLicense)
	if err != nil {
		log.WithError(err).Fatal("Failed to marshal license")
	}

	signedLicense := license.SignedLicense{
		LicenseJSON: string(licenseBytes),
		Signature: ed25519.Sign(privKey, licenseBytes),
	}
	signedLicenseBytes, err := json.Marshal(signedLicense)
	if err != nil {
		log.WithError(err).Fatal("Failed to marshal signed license")
	}

	err = ioutil.WriteFile(outputPath, []byte(signedLicenseBytes), 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write license: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("Successfully wrote license to '%s'\n", outputPath)
}
