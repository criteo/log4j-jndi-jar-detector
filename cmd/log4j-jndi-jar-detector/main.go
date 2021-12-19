package main

import (
	"fmt"
	"os"

	"github.com/criteo/log4j-jndi-detector/internal/detector"
	"github.com/spf13/cobra"
)

var Reporters []string

var rootCmd = &cobra.Command{
	Use:   "log4j-jndi-jar-detector",
	Short: "Detect the running jars vulnerable to log4j JNDI expoits",
	Long:  "Detect the running jars vulnerable to log4j JNDI expoits",
	Run: func(cmd *cobra.Command, args []string) {
		detector.RunDetection(Reporters)
	},
}

func main() {
	rootCmd.Flags().StringSliceVarP(&Reporters, "reporters", "r", []string{"stdout"}, "Reporters to use (stdout, elasticsearch)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
