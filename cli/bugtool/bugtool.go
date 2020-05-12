package bugtool

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	"github.com/kelda-inc/blimp/pkg/cfgdir"
	"github.com/kelda-inc/blimp/pkg/version"
)

var fs = afero.NewOsFs()

func New() *cobra.Command {
	var out string
	cmd := cobra.Command{
		Use:   "bug-tool",
		Short: "Generate an archive for blimp debugging",
		Run: func(_ *cobra.Command, args []string) {
			if err := run(out); err != nil {
				log.Fatal(err)
			}
		},
	}
	cmd.Flags().StringVarP(&out, "out", "o", "", "path to write archive to")
	return &cmd
}

func run(out string) error {
	tmpdir, err := afero.TempDir(fs, "", "kelda-bug-tool")
	if err != nil {
		return fmt.Errorf("Failed to create report directory:\n%s", err)
	}

	defer func() {
		err := fs.RemoveAll(tmpdir)
		if err != nil {
			log.Errorf("could not remove tmp dir: %s", err)
		}
	}()

	setupReports(tmpdir)

	if out == "" {
		out = fmt.Sprintf("blimp-bug-info-%s.tar.gz",
			time.Now().Format("Jan_02_2006-15-04-05"))
	}

	if err := tarDirectory(tmpdir, out); err != nil {
		return fmt.Errorf("Failed to tar:\n%s", err)
	}

	msg := `Created bug information archive at '%s'.
	Please send it to the Kelda team at 'kevin@kelda.io'.
	You may want to edit the archive if your deployment contains sensitive information.
	`
	fmt.Printf(msg, out)
	return nil
}

func setupReports(dir string) {
	//Add more bug reports here.
	var err error
	err = reportCliVersion(dir)
	if err != nil {
		log.Errorf("version reporting failed because: %s", err)
	}

	err = reportDocker(dir)
	if err != nil {
		log.Errorf("docker reporting failed because: %s", err)
	}

	err = reportOs(dir)
	if err != nil {
		log.Errorf("os reporting failed because: %s", err)
	}

	err = copyFileToDir(cfgdir.CLILogFile(), dir)
	if err != nil {
		log.Errorf("failed to report cli log file because: %s", err)
	}

	err = reportSyncthingLogs(cfgdir.ConfigDir, dir)
	if err != nil {
		log.Errorf("failed to report syncthing log files because: %s", err)
	}
}

func reportCliVersion(dir string) error {
	return writeToReportFile(filepath.Join(dir, "cli-version.txt"), version.Version)
}

func reportDocker(dir string) error {
	dockerInfo, err := exec.Command("docker", "info").Output()
	if err != nil {
		return fmt.Errorf("failed to get docker info: %s ", err)
	}
	return writeToReportFile(filepath.Join(dir, "docker-info.txt"), string(dockerInfo))
}

func reportOs(dir string) error {
	osInfo, err := exec.Command("uname", "-a").Output()
	if err != nil {
		return fmt.Errorf("failed to get os info: %s ", err)
	}
	return writeToReportFile(filepath.Join(dir, "os-info.txt"), string(osInfo))
}

func reportSyncthingLogs(logsPath, reportPath string) error {
	syncthingLogRegex := regexp.MustCompile(`syncthing\.*\d*\.log$`)
	return afero.Walk(fs, logsPath, func(file string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !fi.Mode().IsRegular() {
			return nil
		}

		if isSyncthingLog := syncthingLogRegex.MatchString(file); !isSyncthingLog {
			return nil
		}
		return copyFileToDir(file, reportPath)
	})
}

func writeToReportFile(path, content string) error {
	reportFile, err := fs.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %s ", err)
	}
	defer reportFile.Close()

	_, err = reportFile.WriteString(content)
	if err != nil {
		return fmt.Errorf("failed to save %s", reportFile)
	}
	return nil
}

func copyFileToDir(src, dir string) error {
	in, err := fs.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open: %s", src)
	}
	defer in.Close()

	realFileName := filepath.Base(in.Name())
	out, err := fs.Create(filepath.Join(dir, realFileName))
	if err != nil {
		return fmt.Errorf("failed to create: %s", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("failed to copy file %s to %s", in, out)
	}
	return nil
}

func tarDirectory(src, outPath string) error {
	out, err := fs.Create(outPath)
	if err != nil {
		return fmt.Errorf("open destination failed: %s", err)
	}
	defer out.Close()

	gzw := gzip.NewWriter(out)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	return afero.Walk(fs, src, func(file string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(fi, fi.Name())
		if err != nil {
			return fmt.Errorf("make header %s", file)
		}

		relPath, err := filepath.Rel(src, file)
		if err != nil {
			return fmt.Errorf("get relative path %q: %w", file, err)
		}

		header.Name = filepath.Join("blimp-bug-info", relPath)
		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("write %s header", file)
		}

		// Only write contents if it's a file (i.e. not a directory).
		if !fi.Mode().IsRegular() {
			return nil
		}

		f, err := os.Open(file)
		if err != nil {
			return fmt.Errorf("open %s", file)
		}
		defer f.Close()

		if _, err := io.Copy(tw, f); err != nil {
			return fmt.Errorf("open %s", file)
		}
		return nil
	})
}
