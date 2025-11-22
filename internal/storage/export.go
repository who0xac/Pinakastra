package storage

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"
)

type Exporter struct {
	storage *Storage
}

func NewExporter(storage *Storage) *Exporter {
	return &Exporter{storage: storage}
}

func (e *Exporter) ExportJSON(domain string, results *ScanResult) (string, error) {
	path := filepath.Join(e.storage.GetDomainPath(domain), "report.json")

	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", err
	}

	return path, nil
}

func (e *Exporter) ExportCSV(domain string, results *ScanResult) (string, error) {
	path := filepath.Join(e.storage.GetDomainPath(domain), "report.csv")

	file, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{"Tool", "Success", "Findings", "Duration", "Error"}
	if err := writer.Write(header); err != nil {
		return "", err
	}

	// Write data
	for toolName, result := range results.Results {
		row := []string{
			toolName,
			fmt.Sprintf("%t", result.Success),
			fmt.Sprintf("%d", result.Findings),
			result.Duration.String(),
			result.Error,
		}
		if err := writer.Write(row); err != nil {
			return "", err
		}
	}

	return path, nil
}

func (e *Exporter) ExportHTML(domain string, results *ScanResult) (string, error) {
	path := filepath.Join(e.storage.GetDomainPath(domain), "report.html")

	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pinakastra Report - {{.Domain}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0a0f; color: #e0e0e0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #00d4ff; margin-bottom: 10px; }
        .meta { color: #888; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: #1a1a2e; padding: 20px; border-radius: 10px; border: 1px solid #333; }
        .card h3 { color: #00d4ff; font-size: 14px; margin-bottom: 10px; }
        .card .value { font-size: 32px; font-weight: bold; }
        .success { color: #00ff88; }
        .failed { color: #ff4444; }
        table { width: 100%; border-collapse: collapse; background: #1a1a2e; border-radius: 10px; overflow: hidden; }
        th, td { padding: 15px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #252540; color: #00d4ff; }
        tr:hover { background: #252540; }
        .badge { padding: 5px 10px; border-radius: 5px; font-size: 12px; }
        .badge-success { background: #00ff8833; color: #00ff88; }
        .badge-error { background: #ff444433; color: #ff4444; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 Pinakastra Scan Report</h1>
        <p class="meta">Domain: {{.Domain}} | Generated: {{.Timestamp.Format "2006-01-02 15:04:05"}}</p>

        <div class="summary">
            <div class="card">
                <h3>TOTAL TOOLS</h3>
                <div class="value">{{len .Results}}</div>
            </div>
            <div class="card">
                <h3>SUCCESSFUL</h3>
                <div class="value success">{{.SuccessCount}}</div>
            </div>
            <div class="card">
                <h3>FAILED</h3>
                <div class="value failed">{{.FailedCount}}</div>
            </div>
            <div class="card">
                <h3>TOTAL FINDINGS</h3>
                <div class="value">{{.TotalFindings}}</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Tool</th>
                    <th>Status</th>
                    <th>Findings</th>
                    <th>Duration</th>
                    <th>Error</th>
                </tr>
            </thead>
            <tbody>
                {{range $name, $result := .Results}}
                <tr>
                    <td><strong>{{$name}}</strong></td>
                    <td>
                        {{if $result.Success}}
                        <span class="badge badge-success">✓ Success</span>
                        {{else}}
                        <span class="badge badge-error">✗ Failed</span>
                        {{end}}
                    </td>
                    <td>{{$result.Findings}}</td>
                    <td>{{$result.Duration}}</td>
                    <td>{{$result.Error}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
</body>
</html>`

	t, err := template.New("report").Parse(tmpl)
	if err != nil {
		return "", err
	}

	file, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Calculate stats
	data := struct {
		*ScanResult
		SuccessCount  int
		FailedCount   int
		TotalFindings int
	}{
		ScanResult: results,
	}

	for _, r := range results.Results {
		if r.Success {
			data.SuccessCount++
		} else {
			data.FailedCount++
		}
		data.TotalFindings += r.Findings
	}

	if err := t.Execute(file, data); err != nil {
		return "", err
	}

	return path, nil
}

func (e *Exporter) ExportAll(domain string, results *ScanResult) ([]string, error) {
	var paths []string

	// Set timestamp if not set
	if results.Timestamp.IsZero() {
		results.Timestamp = time.Now()
	}

	jsonPath, err := e.ExportJSON(domain, results)
	if err == nil {
		paths = append(paths, jsonPath)
	}

	csvPath, err := e.ExportCSV(domain, results)
	if err == nil {
		paths = append(paths, csvPath)
	}

	htmlPath, err := e.ExportHTML(domain, results)
	if err == nil {
		paths = append(paths, htmlPath)
	}

	return paths, nil
}
