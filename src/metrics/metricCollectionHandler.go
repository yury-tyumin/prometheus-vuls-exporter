package metrics

import (
	"fmt"
	"log"
	"net/http"
	"sort"

	"prometheus-vuls-exporter/utils"
)

func collectReports(reportPath string, cvssVersion string, ignoreUnfixed bool, skipSummary bool) {

	// Read reports from path, remove `current` link
	reportsDir = utils.ReadDir(reportsPath)
	reportsDir = utils.FilterCurrent(reportsDir)

	// Sort directories by their Modified Date, descending
	sort.Slice(reportsDir, func(i, j int) bool {
		return reportsDir[i].ModTime().Unix()-reportsDir[j].ModTime().Unix() > 0
	})

	// Get very first element in the sorted reports, and see if it changed
	latest := reportsDir[0]
	if reportedAt.Unix() == latest.ModTime().Unix() {
		// Timestamps are the same, return
		return
	} else {
		// Timestamps differ, collect report again
		reports = []Report{}

		reportedAt = latest.ModTime()

		latestPath = fmt.Sprintf("%s/%s", reportsPath, latest.Name())
		latestDir = utils.ReadDir(latestPath)

		// Get only JSON files
		reportFiles := utils.AcceptJSON(latestDir)

		// Parse each JSON file and record the result
		for _, file := range reportFiles {
			report := parseReport(file, cvssVersion, ignoreUnfixed, skipSummary)
			reports = append(reports, report)
		}
	}

}

func MetricCollectionHandler(path string, cvssVersion string, ignoreUnfixed bool, skipSummary bool) func(http.HandlerFunc) http.HandlerFunc {
	reportsPath = path
	reportsDir = utils.ReadDir(reportsPath)
	log.Printf("Reports folder configured: %s", reportsPath)

	return func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Gather data from report files and write it
			collectReports(reportsPath, cvssVersion, ignoreUnfixed, skipSummary)

			// Trigger recording of all metrics in `metrics` variable
			for _, metric := range metrics {
				metric.record(metric)
			}

			// Serve next request
			h.ServeHTTP(w, r)
		}
	}
}
