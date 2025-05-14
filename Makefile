all:
	go build -o skyagent main.go plane.go server.go starlink.go

plane:
	GOOS=linux GOARCH=amd64 go build -o plane_agent main.go plane.go starlink.go

server:
	GOOS=linux GOARCH=amd64 go build -o server_agent main.go server.go