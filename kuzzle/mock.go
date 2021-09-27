package kuzzle

type Mock struct {
	enabled    bool
	statusCode int
	url        string
	route      string
	response   interface{}
}
