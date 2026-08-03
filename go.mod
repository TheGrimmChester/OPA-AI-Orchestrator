module github.com/TheGrimmChester/ora-api

go 1.25.0

require (
	github.com/TheGrimmChester/open-client-go v0.0.0
	github.com/TheGrimmChester/open-job-go v0.0.0
	github.com/golang-jwt/jwt/v5 v5.3.1
)

require github.com/TheGrimmChester/open-auth-go v0.0.0 // indirect

replace github.com/TheGrimmChester/open-auth-go => ../Open-Auth-Go

replace github.com/TheGrimmChester/open-client-go => ../Open-Client-Go

replace github.com/TheGrimmChester/open-job-go => ../Open-Job-Go
