module github.com/yktsubo/ofnet

go 1.13

require (
	github.com/Microsoft/go-winio v0.4.14
	github.com/cenk/hub v1.0.1 // indirect
	github.com/cenkalti/hub v1.0.1 // indirect
	github.com/cenkalti/rpc2 v0.0.0-20200203073230-5ce2854ce0fd // indirect
	github.com/contiv/libOpenflow v0.0.0-20200319171453-882ba6d92cbc
	github.com/contiv/libovsdb v0.0.0-20170227191248-d0061a53e358
	github.com/sirupsen/logrus v1.4.2
	github.com/streamrail/concurrent-map v0.0.0-20160823150647-8bf1e9bacbf6
	github.com/stretchr/testify v1.5.1
	github.com/wenyingd/ofnet v0.0.0-20200306115935-b1f7790fe2be // indirect
)

replace github.com/contiv/libOpenflow => github.com/yktsubo/libOpenflow v0.2.0
