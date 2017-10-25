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
	"github.com/smallnest/iprange"
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
	targetNic, ipMask     string
	securityGroups, ports []string
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func toInt(s string) int64 {
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}

func getPublicIp() ([]byte, error) {
	rsp, err := http.Get("http://checkip.amazonaws.com")
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
	for _, port := range ports {
		for _, v := range grp.IpPermissions {
			if strings.Contains(v.String(), port) {
				log.Println("Revoking", v.String())
				// revoke
				portI := toInt(port)
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
	}
	perms := make([]*ec2.IpPermission, len(ports))
	for i, v := range ports {
		port := toInt(v)
		perms[i] = (&ec2.IpPermission{}).
			SetIpProtocol("tcp").
			SetFromPort(port).
			SetToPort(port).
			SetIpRanges([]*ec2.IpRange{
				{CidrIp: aws.String(fmt.Sprintf("%s/32", strings.TrimSpace(string(ip))))},
			})
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

func getIfaceIp() (net.IP, bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Println(err.Error())
		return nil, false
	}
	ipMaskRange := iprange.ParseIPV4Range(ipMask)
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		if strings.Contains(iface.Name, targetNic) {
			for _, addr := range addrs {
				ip := net.ParseIP(strings.Split(addr.String(), "/")[0])
				if iprange.IPv4Contains(ipMaskRange, ip) {
					// found valid ip
					return ip, true
				}
			}
			return nil, false
		}
	}
	return nil, false
}

func listenForIpChanges(quit chan bool) error {
	sleep := 3 * time.Second
	currentIp, ok := getIfaceIp()
	if !ok {
		return errors.New("disconnected")
	}
	t := time.NewTicker(sleep)
OUTER:
	for {
		select {
		case <-quit:
			break OUTER
		case <-t.C:
			nextIp, ok := getIfaceIp()
			if ok {
				if !currentIp.Equal(nextIp) {
					// ip has changed, set security group
					log.Println("ip has changed", currentIp, "=>", nextIp)
					currentIp = nextIp
					jitter := time.Duration(rand.Int63n(int64(sleep)))
					sleep = sleep + jitter/2
				} else {
					// log.Println("ip is still the same", currentIp, "==", nextIp)
					jitter := time.Duration(rand.Int63n(int64(sleep) + 40))
					sleep = sleep + jitter/2
				}
				t.Stop()
				t = time.NewTicker(sleep)

			} else {
				return errors.New("disconnected")
			}
		}
	}
	log.Println("stop watching")
	return nil
}

func waitForReconnection(quit chan bool) (net.IP, error) {
	sleep := 5 * time.Second
	t := time.NewTicker(sleep)
OUTER:
	for {
		select {
		case <-quit:

			break OUTER
		case <-t.C:
			nextIp, ok := getIfaceIp()
			if ok {
				// ip has changed, set security group
				log.Println("ip has been retrieved", nextIp)
				return nextIp, nil

			} else {
				jitter := time.Duration(rand.Int63n(int64(sleep) + 40))
				sleep = sleep + jitter/2
				t.Stop()
				t = time.NewTicker(sleep)
			}
		}
	}
	log.Println("stop waiting for reconnection")
	return nil, nil
}

func watcher(svc *ec2.EC2, quit chan bool) error {
	setPortIngressSource(svc, securityGroups[0], ports)
	if err := listenForIpChanges(quit); err != nil {
		// we got disconnected wait for reconnection then listen again
		log.Println("internet connection lost")
		_, err = waitForReconnection(quit)
		if err == nil {
			return watcher(svc, quit)
		}
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
			log.Println("watcher failed", err.Error())
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
	watchCmd.Flags().StringVarP(&targetNic, "interface", "i", "New Virtual Switch", "Interface to watch for changes")
	watchCmd.Flags().StringVarP(&ipMask, "mask", "m", "192.168.1.1/24", "ip found has to match this mask")
	watchCmd.Flags().StringArrayVarP(&securityGroups, "groups", "g", []string{"launch-wizard-1"}, "ec2 security groups to modify")
	watchCmd.Flags().StringArrayVarP(&ports, "ports", "t", []string{"2376"}, "ports to modify")
}
