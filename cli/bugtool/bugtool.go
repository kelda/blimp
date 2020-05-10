package bugtool

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"

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
	err := reportVersion(dir)
	if err != nil {
		log.Errorf("version reporting failed because: %s", err)
	}
}

func reportVersion(dir string) error {
	versionInfo, err := fs.Create(filepath.Join(dir, "cli-version.txt"))
	if err != nil {
		return fmt.Errorf("failed to create blimp cli info file: %s ", err)
	}
	defer versionInfo.Close()

	_, err = versionInfo.WriteString(version.Version)
	if err != nil {
		return fmt.Errorf("failed to save %s", versionInfo)
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
