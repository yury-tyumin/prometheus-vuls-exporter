package metrics

import (
	"fmt"
	"os"
	"prometheus-vuls-exporter/utils"
	"strings"

	"github.com/tidwall/gjson"
)

func getterFactory(jsonString string) func(path string, a ...interface{}) gjson.Result {
	return func(path string, a ...interface{}) gjson.Result {
		finalPath := fmt.Sprintf(path, a...)
		// log.Printf("Trying to get data at path: %s", finalPath)
		return gjson.Get(jsonString, finalPath)
	}
}

func getServerName(file os.FileInfo) string {
	filename := file.Name()
	lastDot := strings.LastIndex(filename, ".")
	serverName := filename[0:lastDot]
	return serverName
}

//  removeDuplicateValues removes duplicates from a slice of string
func removeDuplicateValues(stringSlice []string) []string {
	keys := make(map[string]bool)
	results := []string{}

	for _, entry := range stringSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			results = append(results, entry)
		}
	}
	return results
}

// Function to determine the preferred CVSS version
func getCvssSeverity(c gjson.Result, preferredVersion string) string {

	var severityAttribute string
	switch preferredVersion {
	case "v4":
		severityAttribute = "cvss40Severity"
	case "v3":
		severityAttribute = "cvss3Severity"
	case "v2":
		severityAttribute = "cvss2Severity"
	default:
		return "UNKNOWN"
	}

	return getCveContentValue(c, severityAttribute)
}

func getCveContentValue(c gjson.Result, attribute string) string {

	path := c.Get(fmt.Sprintf("cveContents.@values.@flatten.#.%s", attribute))

	var slice []string
	for _, sev := range path.Array() {
		slice = append(slice, sev.String())
	}

	unique := removeDuplicateValues(slice)
	if len(unique) > 0 {
		return strings.ToLower(unique[0])
	} else {
		return "UNKNOWN"
	}

}

func parseReport(file os.FileInfo, cvssVersion string) Report {
	var r Report

	// Get basic file info
	filePath := fmt.Sprintf("%s/%s", latestPath, file.Name())
	r.filename = file.Name()
	r.serverName = getServerName(file)
	r.path = filePath

	// log.Printf("Parsing report: %s", file.Name())

	// Get JSON contents
	jsonString := string(utils.ReadFile(filePath))
	getData := getterFactory(jsonString)

	// Basic host information
	r.hostname = getData("config.report.servers.%s.host", r.serverName).String()

	// Kernel information
	r.kernel = KernelInfo{
		rebootRequired: getData("runningKernel.rebootRequired").Bool(),
		release:        getData("runningKernel.release").String(),
	}

	// Vulnerability information
	var cves []CVEInfo
	for _, c := range getData("scannedCves").Map() {
    // Get affected package or CPE URI
    var packageName string
		var fixState string
		var notFixedYet bool
    if c.Get("affectedPackages").Exists() {
        packageName = c.Get("affectedPackages.0.name").String()
				fixState    = c.Get("affectedPackages.0.fixState").String()
				notFixedYet = c.Get("affectedPackages.0.notFixedYet").Bool()
    } else if c.Get("cpeURIs").Exists() {
        packageName = c.Get("cpeURIs.0").String()
				fixState    = ""
				notFixedYet = false
    } else {
				// Fallback: No affectedPackages or cpeURIs available
				packageName = ""
				fixState    = ""
				notFixedYet = false
		}

		cve := CVEInfo{
			id:           c.Get("cveID").String(),
			packageName:  packageName,
			severity:     getCvssSeverity(c, cvssVersion),
			fixState:     fixState,
			notFixedYet:  notFixedYet,
			title:        getCveContentValue(c,"title"),
			summary:      getCveContentValue(c,"summary"),
			published:    getCveContentValue(c,"published"),
			lastModified: getCveContentValue(c,"lastModified"),
			mitigation:   getCveContentValue(c,"mitigation"),
		}
		cves = append(cves, cve)
	}

	r.cves = cves

	// Debug
	// log.Printf("Report:\n")
	// log.Printf("%+v\n\n", r.cves)

	return r
}
