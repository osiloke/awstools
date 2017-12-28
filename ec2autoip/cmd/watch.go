// Copyright © 2017 NAME HERE <EMAIL ADDRESS>
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	// "os"
	// "path/filepath"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"
)

var (
	targetNic             string
	securityGroups, ports []string
	errQuit               = errors.New("quit")
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func toInt(s string) int64 {
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}

func getPublicIp() ([]byte, error) {
	rsp, err := http.Get("https://ifconfig.co/")
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()
	return ioutil.ReadAll(rsp.Body)

}
func getExistingGroup(svc *ec2.EC2, name string) (*ec2.SecurityGroup, error) {
	result, err := svc.DescribeSecurityGroups(
		&ec2.DescribeSecurityGroupsInput{
			GroupNames: aws.StringSlice([]string{name}),
		},
	)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "InvalidGroupId.Malformed":
				fallthrough
			case "InvalidGroup.NotFound":
				return nil, fmt.Errorf("%s.", aerr.Message())
			}
		}
		return nil, fmt.Errorf("Unable to get descriptions for security groups, %v", err)
	}

	return result.SecurityGroups[0], nil
}
func setPortIngressSource(svc *ec2.EC2, name string, ports []string) error {
	ip, err := getPublicIp()
	if err != nil {
		return err
	}
	grp, err := getExistingGroup(svc, name)
	if err != nil {
		return err
	}
	currentCidrIp := fmt.Sprintf("%s/32", strings.TrimSpace(string(ip)))

	perms := []*ec2.IpPermission{}
	for _, port := range ports {
		alreadySet := false
		portI := toInt(port)
		for _, v := range grp.IpPermissions {
			if strings.Contains(v.String(), port) {
				if strings.Contains(currentCidrIp, *v.IpRanges[0].CidrIp) {
					alreadySet = true
					break
				}
				log.Println("Revoking", v.String())
				// revoke
				_, err := svc.RevokeSecurityGroupIngress(&ec2.RevokeSecurityGroupIngressInput{
					GroupName:  aws.String(name),
					IpProtocol: aws.String("tcp"),
					FromPort:   aws.Int64(portI),
					ToPort:     aws.Int64(portI),
					CidrIp:     v.IpRanges[0].CidrIp,
				})
				if err != nil {
					log.Printf("Unable to revoke security group %q ingress port %v, %v", name, port, err)

				} else {
					log.Printf("Revoked security group %q ingress port %v", name, port)
				}
			}
		}
		if !alreadySet {
			perms = append(perms, (&ec2.IpPermission{}).
				SetIpProtocol("tcp").
				SetFromPort(portI).
				SetToPort(portI).
				SetIpRanges([]*ec2.IpRange{
					{CidrIp: aws.String(currentCidrIp)},
				}))
		}
	}
	if len(perms) == 0 {
		log.Println("all ingress ports are still valid")
		return nil
	}

	_, err = svc.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
		GroupName:     aws.String(name),
		IpPermissions: perms,
	})
	if err != nil {
		log.Printf("Unable to set security group %q ingress, %v", name, err)
		return err
	}

	log.Println("Successfully set security group ingress")
	return nil
}

func ifaceUp() bool {
	iface, err := net.InterfaceByName(targetNic)
	if err != nil {
		log.Println(err.Error())
		return false
	}
	// log.Printf("%s addresses %v, flags: %v", iface.Name, addrs, iface.Flags)
	return strings.Contains(iface.Flags.String(), "up")
}

func listenForIpChanges(quit chan bool) error {
	sleep := 3 * time.Second
	ok := ifaceUp()
	if !ok {
		return errors.New("disconnected")
	}
	// _, err := getPublicIp()
	// if err != nil {
	// 	log.Println("unable to get public ip, possible disconnected")
	// 	return err
	// }
	t := time.NewTicker(sleep)
	log.Println("listening for ip changes")
	defer log.Println("stop listening for ip changes")
	defer t.Stop()
	// OUTER:
	for {
		select {
		case <-quit:
			return errQuit
		case <-t.C:
			ok := ifaceUp()
			if !ok {
				log.Println("disconnected")
				return errors.New("disconnected")
			}
		}
	}
	return nil
}

func waitForReconnection(quit chan bool) ([]byte, error) {
	sleep := 2 * time.Second
	t := time.NewTicker(sleep)
	defer t.Stop()
	log.Println("reconnecting...")
	defer log.Println("stop waiting for reconnection")
	// OUTER:
	for {
		select {
		case <-quit:
			return nil, errQuit
		case <-t.C:
			ip, err := getPublicIp()
			if err == nil {
				log.Println("reconnected as", string(ip))
				return ip, nil

			}
			log.Println("reconnecting...")
			//  else {
			// 	jitter := time.Duration(rand.Int63n(int64(sleep)))
			// 	sleep = sleep + jitter/2
			// 	t.Stop()
			// 	t = time.NewTicker(sleep)
			// }
		}
	}

	return nil, nil
}

func watcher(svc *ec2.EC2, quit chan bool) error {
	if err := setPortIngressSource(svc, securityGroups[0], ports); err != nil {
		log.Println(err.Error())
	}
	if err := listenForIpChanges(quit); err != nil {
		// we got disconnected wait for reconnection then listen again
		if err == errQuit {
			return err
		}
		_, err = waitForReconnection(quit)
		if err == nil {
			return watcher(svc, quit)
		}
		if err == errQuit {
			return nil
		}
		return err
	}
	return nil
}

// watchCmd represents the watch command
var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Listen for network events and modify ip of security groups",
	Long:  `Listen for network events and modify ip of security groups.`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("Watching", fmt.Sprintf(`"%s"`, targetNic), "for ip changes")
		signal_chan := make(chan os.Signal, 1)
		signal.Notify(signal_chan,
			syscall.SIGHUP,
			syscall.SIGINT,
			syscall.SIGTERM,
			syscall.SIGQUIT)
		quit := make(chan bool, 1)
		go func(signal_chan chan os.Signal, quit chan bool) {
			select {
			case <-signal_chan:
				quit <- true
			}
		}(signal_chan, quit)
		sess := session.Must(session.NewSessionWithOptions(session.Options{
			SharedConfigState: session.SharedConfigEnable,
		}))
		svc := ec2.New(sess)
		if err := watcher(svc, quit); err != nil {
			if err != errQuit {
				log.Println("watcher failed", err.Error())
			}
		}
	},
}

func init() {
	RootCmd.AddCommand(watchCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// watchCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// watchCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	watchCmd.Flags().StringVarP(&targetNic, "interface", "i", "vEthernet (New Virtual Switch)", "Interface to watch for changes")
	watchCmd.Flags().StringArrayVarP(&securityGroups, "groups", "g", []string{"launch-wizard-1"}, "ec2 security groups to modify")
	watchCmd.Flags().StringArrayVarP(&ports, "ports", "t", []string{"2376"}, "ports to modify")
}
