package main

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/brianloveswords/airtable"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	// Load the client authentication plugin necessary for connecting to GKE.
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

type UserRecord struct {
	airtable.Record

	Fields struct {
		Name      string
		Email     string
		Namespace string
		LastUsage time.Time `json:"Last Usage"`
	}
}

const kubeContext = "gke_kelda-blimp_us-west1-a_customer"

var airtableClient = airtable.Client{
	APIKey: mustGetEnvVar("AIRTABLE_API_KEY"),
	BaseID: mustGetEnvVar("AIRTABLE_BASE_ID"),
}

func main() {
	userRecords, err := getUserRecords()
	if err != nil {
		log.WithError(err).Fatal("Failed to get usage records")
	}

	kubeClient, err := getKubeClient()
	if err != nil {
		log.WithError(err).Fatal("Failed to get kube client")
	}

	namespaces, err := kubeClient.CoreV1().Namespaces().List(metav1.ListOptions{
		LabelSelector: "blimp.sandbox=true",
	})
	if err != nil {
		log.WithError(err).Fatal("Failed to get namespaces")
	}

	var activeUsers []UserRecord
	for _, namespace := range namespaces.Items {
		user, ok := userRecords[namespace.Name]
		if !ok {
			log.WithField("namespace", namespace.Name).Warn("Unknown namespace")
			continue
		}

		activeUsers = append(activeUsers, user)
	}

	sort.Slice(activeUsers, func(i, j int) bool {
		return activeUsers[i].Fields.LastUsage.After(activeUsers[j].Fields.LastUsage)
	})

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
	defer w.Flush()
	fmt.Fprintln(w, "NAMESPACE\tLAST USED\tNAME\tEMAIL")
	for _, user := range activeUsers {
		lastUsed := int(time.Now().Sub(user.Fields.LastUsage).Hours() / 24)
		fmt.Fprintf(w, "%s\t%dd\t%s\t%s\n", user.Fields.Namespace, lastUsed, user.Fields.Name, user.Fields.Email)
	}
}

func getKubeClient() (kubernetes.Interface, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules,
		&clientcmd.ConfigOverrides{CurrentContext: kubeContext})

	restConfig, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("get rest config: %w", err)
	}

	return kubernetes.NewForConfig(restConfig)
}

func getUserRecords() (map[string]UserRecord, error) {
	var users []UserRecord
	table := airtableClient.Table("Blimp Users")
	if err := table.List(&users, &airtable.Options{}); err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}

	usersMap := map[string]UserRecord{}
	for _, user := range users {
		usersMap[user.Fields.Namespace] = user
	}
	return usersMap, nil
}

func mustGetEnvVar(key string) string {
	val := os.Getenv(key)
	if val == "" {
		panic(fmt.Sprintf("%s is required", key))
	}
	return val
}
