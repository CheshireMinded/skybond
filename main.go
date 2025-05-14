package main

import (
	"fmt"
	"os"

	"skybond/plane"
	"skybond/server"
)

func main() {
	role := os.Getenv("SKYAGENT_ROLE")
	switch role {
	case "plane":
		plane.RunPlane()
	case "server":
		server.RunServer()
	default:
		fmt.Println("Set SKYAGENT_ROLE=plane or server")
	}
}
