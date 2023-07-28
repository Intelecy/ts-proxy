package main

import (
	"context"
	"fmt"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapio"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsnet"
	"time"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	app := &cli.App{
		Name: "ts-proxy",
		Authors: []*cli.Author{
			{
				Name:  "Jonathan Camp",
				Email: "jonathan.camp@intelecy.com",
			},
		},
		Copyright:       "Intelecy AS",
		HideHelpCommand: true,
		ArgsUsage:       "-- [command [argument ...]]",
		Usage:           "Forward TCP traffic from Tailscale to a local port/process",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "auth-key",
				EnvVars:  []string{"TS_AUTHKEY"},
				Usage:    "Tailscale auth key. If not provided, manual intervention is required.",
				Category: "Tailscale:",
			},
			&cli.PathFlag{
				Name:     "state-dir",
				EnvVars:  []string{"TS_STATEDIR"},
				Usage:    "Tailscale state directory",
				Category: "Tailscale:",
			},
			&cli.StringFlag{
				Name:     "hostname",
				Value:    hostname,
				Usage:    "Tailscale machine name (must be unique)",
				Category: "Tailscale:",
			},
			&cli.StringSliceFlag{
				Name:  "port",
				Usage: "forward incoming TCP connections to local port. can be repeated (src_port:dst_port)",

				Action: func(_ *cli.Context, strings []string) error {
					re := regexp.MustCompile(`^\d+:\d+$`)
					for _, s := range strings {
						if !re.MatchString(s) {
							return fmt.Errorf("invalid port map %s. must be `uint16:uint16`", s)
						}
					}
					return nil
				},
			},
		},
		Action: run,
	}

	if err := app.RunContext(ctx, os.Args); err != nil && err != context.Canceled {
		panic(err)
	}
}

func run(c *cli.Context) (err error) {
	ctx, cancel := context.WithCancelCause(c.Context)

	defer func() {
		if cerr := context.Cause(ctx); cerr != nil {
			if cerr != context.Canceled {
				if err != nil {
					err = errors.Wrap(err, cerr.Error())
				} else {
					err = cerr
				}
			}
		}
		cancel(nil)
	}()

	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	if c.Args().Len() == 0 {
		logger.Warn("no command given!")
	} else {
		cmd := exec.CommandContext(ctx, c.Args().First(), c.Args().Slice()[1:]...)
		writer := &zapio.Writer{Log: logger.Named(c.Args().First()), Level: zap.DebugLevel}
		defer writer.Close()

		// capture stdout/err and write to logger
		cmd.Stderr = writer
		cmd.Stdout = writer

		go func() {
			if err := cmd.Run(); err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					// ignore sigint
					if ee.ExitCode() == -1 {
						return
					}
				}
				cancel(err)
			}
		}()

		// give the process a bit of time to start up and catch process errors before continuing
		time.Sleep(time.Millisecond * 100)

		select {
		case <-ctx.Done():
			// error will be captured by cancel(cause)
			return nil
		default:
		}
	}

	logf := logger.Sugar().Named("tailscale").Debugf
	store, err := mem.New(logf, "")
	if err != nil {
		return err
	}

	s := &tsnet.Server{
		AuthKey:   c.String("auth-key"),
		Logf:      logf,
		Store:     store,
		Ephemeral: true,
		Hostname:  c.String("hostname"),
		Dir:       c.Path("state-dir"),
	}

	if err := s.Start(); err != nil {
		return err
	}

	defer func() {
		// s.Close() doesn't seem to correctly logout _if_ the store is mem. :shrug:
		lc, _ := s.LocalClient()
		_ = lc.Logout(context.TODO()) // can't use the parent context here because by the time we hit this, it is probably canceled

		_ = s.Close()
	}()

	status, err := s.Up(ctx)
	if err != nil {
		return err
	}

	// check if we have a duplicate host name
	if strings.Join([]string{status.Self.HostName, status.CurrentTailnet.MagicDNSSuffix, ""}, ".") != status.Self.DNSName {
		return fmt.Errorf("hostname %s already in use", status.Self.HostName)
	}

	lc, err := s.LocalClient()
	if err != nil {
		return err
	}

	portHandlerMap := make(map[uint16]*ipn.TCPPortHandler)

	for _, portDef := range c.StringSlice("port") {
		// note: portDef format is checked during flag parsing
		src, dst, _ := strings.Cut(portDef, ":")
		srcPort, _ := strconv.Atoi(src)

		portHandlerMap[uint16(srcPort)] = &ipn.TCPPortHandler{
			TCPForward: fmt.Sprintf("localhost:%s", dst),
		}
	}

	if err := lc.SetServeConfig(ctx, &ipn.ServeConfig{
		TCP: portHandlerMap,
	}); err != nil {
		return err
	}

	<-ctx.Done()

	return context.Cause(ctx)
}
