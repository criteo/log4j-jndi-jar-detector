package main

import (
	"fmt"
	"os"
	"time"

	"github.com/criteo/log4j-jndi-detector/internal/detector"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var Reporters []string
var Daemon bool
var DaemonInterval time.Duration
var Verbose bool
var SafeVersion string

var rootCmd = &cobra.Command{
	Use:   "log4j-jndi-jar-detector",
	Short: "Detect the running jars vulnerable to log4j JNDI expoits",
	Long:  "Detect the running jars vulnerable to log4j JNDI expoits",
	Run: func(cmd *cobra.Command, args []string) {
		if Verbose {
			logrus.SetLevel(logrus.DebugLevel)
		}

		detector.RunDetection(Reporters, Daemon, DaemonInterval, SafeVersion)
	},
}

func main() {
	rootCmd.Flags().StringSliceVarP(&Reporters, "reporters", "r", []string{"stdout"}, "Reporters to use (stdout, elasticsearch)")
	rootCmd.Flags().BoolVarP(&Daemon, "daemon", "d", false, "enable/disable daemon mode")
	rootCmd.Flags().DurationVarP(&DaemonInterval, "interval", "i", 15*time.Minute, "duration between intervals in daemon mode")
	rootCmd.Flags().BoolVarP(&Verbose, "verbose", "", false, "enable verbose logs")
	rootCmd.Flags().StringVarP(&SafeVersion, "safe-version", "", "2.16.0", "version from which we consider the library to be safe")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
