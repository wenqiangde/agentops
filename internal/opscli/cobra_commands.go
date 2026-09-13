package opscli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/wenqiangde/agentops/internal/paths"
)

type commandSpec struct {
	Name  string
	Use   string
	Short string
}

func executeAgentOpsCommand(p paths.Paths, args []string, stdout, stderr io.Writer) int {
	code := 0
	root := newRootCommand(p, stdout, stderr, &code)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		return opsUsageError(stderr, err.Error())
	}
	return code
}

func newRootCommand(p paths.Paths, stdout, stderr io.Writer, code *int) *cobra.Command {
	root := &cobra.Command{
		Use:           "agentops",
		Short:         "Operate application services",
		SilenceErrors: true,
		SilenceUsage:  true,
		Run: func(_ *cobra.Command, _ []string) {
			*code = opsCommand(p, nil, stdout, opsUsageWriter{Writer: stderr, usage: agentOpsUsage})
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.Version = versionText()
	root.SetVersionTemplate("{{.Version}}")

	for _, spec := range operationCommandSpecs() {
		spec := spec
		command := &cobra.Command{
			Use:                spec.Use,
			Short:              spec.Short,
			DisableFlagParsing: true,
			SilenceErrors:      true,
			SilenceUsage:       true,
			Run: func(cmd *cobra.Command, commandArgs []string) {
				if isHelpArgs(commandArgs) {
					_ = cmd.Help()
					return
				}
				fullArgs := append([]string{spec.Name}, commandArgs...)
				*code = opsCommand(p, fullArgs, stdout, opsUsageWriter{Writer: stderr, usage: agentOpsUsage})
			},
		}
		root.AddCommand(command)
	}

	root.AddCommand(newVersionCommand(stdout), newCompletionCommand(stdout))
	cobra.EnableCommandSorting = false
	return root
}

func operationCommandSpecs() []commandSpec {
	return []commandSpec{
		{Name: "validate", Use: "validate <all|service>", Short: "Validate the service inventory"},
		{Name: "list", Use: "list [--language <language>] [--host <host>]", Short: "List configured services"},
		{Name: "inspect", Use: "inspect <service> [--environment <local|production>]", Short: "Inspect a service runtime"},
		{Name: "build", Use: "build <service>", Short: "Build a service release artifact"},
		{Name: "health", Use: "health <service|all> --environment <local|production>", Short: "Check service health"},
		{Name: "deploy", Use: "deploy <service> --environment production --version <version>", Short: "Deploy a service release"},
		{Name: "rollback", Use: "rollback <service> --environment production --version <version>", Short: "Roll back a service release"},
		{Name: "backup", Use: "backup <service> --environment production", Short: "Create an encrypted service backup"},
	}
}

func newVersionCommand(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show AgentOps build information",
		Args:  cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Fprint(stdout, versionText())
		},
	}
}

func newCompletionCommand(stdout io.Writer) *cobra.Command {
	completion := &cobra.Command{Use: "completion", Short: "Generate shell completion"}
	completion.AddCommand(
		&cobra.Command{Use: "bash", Short: "Generate Bash completion", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Root().GenBashCompletion(stdout)
		}},
		&cobra.Command{Use: "zsh", Short: "Generate Zsh completion", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Root().GenZshCompletion(stdout)
		}},
		&cobra.Command{Use: "fish", Short: "Generate Fish completion", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Root().GenFishCompletion(stdout, true)
		}},
	)
	return completion
}

func isHelpArgs(args []string) bool {
	return len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h")
}
