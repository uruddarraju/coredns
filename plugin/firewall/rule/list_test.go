package rule

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/policy"
	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

type testEngine struct {
	err    error
	result int
}

func (r *testEngine) Evaluate(data interface{}) (int, error) {
	return r.result, r.err
}

type stubEngine struct {
	name        string
	alwaysError bool
}

func (e *stubEngine) BuildQueryData(ctx context.Context, state request.Request) (interface{}, error) {
	if e.alwaysError {
		return nil, fmt.Errorf("engine %s is returning an error at buildQueryData", e.name)
	}
	return e.name, nil
}

func (e *stubEngine) BuildReplyData(ctx context.Context, state request.Request, query interface{}) (interface{}, error) {
	if e.alwaysError {
		return nil, fmt.Errorf("engine %s is returning an error at buildReplyData", e.name)
	}
	return e.name, nil
}

func (e *stubEngine) BuildRule(args []string) (policy.Rule, error) {
	if e.alwaysError {
		return nil, fmt.Errorf("engine %s is returning an error at BuildRule", e.name)
	}
	r := policy.TypeNone
	var err error
	if len(args) > 0 {
		v, errconv := strconv.Atoi(args[0])
		if errconv != nil {
			err = fmt.Errorf("rule from %s, evalute as an error : %s", e.name, args[0])
		} else {
			r = v
		}
	}
	return &testEngine{err, r}, nil
}

func TestEnsureRules(t *testing.T) {
	engines := map[string]policy.Engine{
		"good":  &stubEngine{"good", false},
		"wrong": &stubEngine{"wrong", true},
	}

	tests := []struct {
		rules []*Element
		error bool
	}{
		// unknown engine
		{[]*Element{{"plugin", "unknown", []string{}, nil},
			{"plugin", "good", []string{}, nil}},
			true,
		},
		// invalid params
		{[]*Element{{"plugin", "wrong", []string{}, nil},
			{"plugin", "good", []string{}, nil}},
			true,
		},
		// all ok
		{[]*Element{{"plugin", "good", []string{}, nil},
			{"plugin", "good", []string{}, nil}},
			false,
		},
	}
	for i, test := range tests {
		rl, _ := NewList(policy.TypeDrop, false)
		rl.RuleList = test.rules

		err := rl.EnsureEngine(engines)
		if err != nil {
			if !test.error {
				t.Errorf("Test %d : unexpected error at build rule : %s", i, err)
			}
			continue
		}
		if test.error {
			t.Errorf("Test %d : no error at EnsureRules returned, when one was expected", i)
		}
	}
}

func TestEvaluate(t *testing.T) {

	engines := map[string]policy.Engine{
		"good":  &stubEngine{"good", false},
		"wrong": &stubEngine{"wrong", true},
	}

	tests := []struct {
		rules []*Element
		error bool
		value int
	}{

		// error at query data
		{[]*Element{{"plugin", "wrong", []string{}, nil},
			{"plugin", "good", []string{}, nil}},
			true, policy.TypeNone,
		},
		// error at reply data
		{[]*Element{{"plugin", "wrong", []string{}, nil},
			{"plugin", "good", []string{}, nil}},
			true, policy.TypeNone,
		},
		// error returned by evaluation
		{[]*Element{{"plugin", "good", []string{"Error returned"}, nil},
			{"plugin", "good", []string{}, nil}},
			true, policy.TypeNone,
		},
		// invalid value returned by evaluation
		{[]*Element{{"plugin", "good", []string{"123"}, nil},
			{"plugin", "good", []string{}, nil}},
			true, policy.TypeNone,
		},
		// a correct value is returned by the rulelist
		{[]*Element{
			{"plugin", "good", []string{"0"}, nil},
			{"plugin", "good", []string{"0"}, nil},
			{"plugin", "good", []string{"0"}, nil},
			{"plugin", "good", []string{"2"}, nil}},
			false, policy.TypeAllow,
		},
		// no value is returned by the rulelist
		{[]*Element{
			{"plugin", "good", []string{"0"}, nil},
			{"plugin", "good", []string{"0"}, nil},
			{"plugin", "good", []string{"0"}, nil}},
			false, policy.TypeDrop,
		},
	}
	for i, tst := range tests {
		rl, _ := NewList(policy.TypeDrop, false)
		rl.RuleList = tst.rules
		rl.EnsureEngine(engines)

		state := request.Request{W: &test.ResponseWriter{}, Req: new(dns.Msg)}
		state.Req.SetQuestion("example.org.", dns.TypeA)

		ctx := context.TODO()
		data := make(map[string]interface{})
		result, err := rl.Evaluate(ctx, state, data, engines)
		if err != nil {
			if !tst.error {
				t.Errorf("Test %d : unexpected error at evaluate rulelist : %s", i, err)
			}
			continue
		}
		if tst.error {
			t.Errorf("Test %d : no error at evaluate rulelist returned, when one was expected", i)
			continue
		}
		if result != tst.value {
			t.Errorf("Test %d : value return is not the one expected - expected : %v, got : %v", i, tst.value, result)
			continue
		}

	}
}
