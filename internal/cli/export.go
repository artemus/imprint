package cli

import (
	"context"
	"fmt"
	"io"
	"path/filepath"

	"github.com/artemus/imprint/internal/canonical"
	"github.com/artemus/imprint/internal/privateio"
	"github.com/artemus/imprint/internal/projection"
)

func runExport(args []string, configPath string, stdout, stderr io.Writer) int {
	format, output := "", ""
	for index := 1; index < len(args); index += 2 {
		if index+1 >= len(args) {
			return fail(stderr, "export options require values")
		}
		switch args[index] {
		case "--format":
			format = args[index+1]
		case "--output":
			output = args[index+1]
		default:
			return fail(stderr, "unknown export option "+args[index])
		}
	}
	if format != "markdown" {
		return fail(stderr, "native export currently supports --format markdown")
	}
	runtime, err := loadRuntime(configPath, true)
	if err != nil {
		return fail(stderr, err.Error())
	}
	database, err := runtime.openStore()
	if err != nil {
		return fail(stderr, err.Error())
	}
	defer database.Close()
	snapshot, err := database.ProjectionState(context.Background())
	if err != nil {
		return fail(stderr, err.Error())
	}
	content := projection.Markdown(snapshot)
	if output == "" {
		fmt.Fprint(stdout, content)
		return 0
	}
	absolute, err := filepath.Abs(output)
	if err != nil {
		return fail(stderr, err.Error())
	}
	if err = privateio.PublishNew(absolute, []byte(content)); err != nil {
		return fail(stderr, err.Error())
	}
	response, _ := canonical.JSON(map[string]string{"status": "exported", "path": absolute})
	fmt.Fprintln(stdout, string(response))
	return 0
}
