package rule

import (
	"context"
	"fmt"
	"strings"

	"github.com/coredns/coredns/plugin/pkg/policy"
	"github.com/coredns/coredns/request"
)

type Element struct {
	Name   string
	Plugin string
	Params []string
	Rule   policy.Rule
}

type List struct {
	reply         bool
	RuleList      []*Element
	DefaultPolicy int
}

func NewList(ifNoResult int, isReply bool) (*List, error) {
	if ifNoResult >= policy.TypeCount {
		return nil, fmt.Errorf("invalid default rulelist parameters: %v", ifNoResult)
	}
	return &List{reply: isReply, DefaultPolicy: ifNoResult}, nil
}

func (p *List) EnsureEngine(engines map[string]policy.Engine) error {
	var err error
	for _, re := range p.RuleList {
		if re.Rule == nil {
			e, ok := engines[re.Name]
			if !ok {
				return fmt.Errorf("unknown engine for plugin %s and name %s - cannot build the rule", re.Plugin, re.Name)
			}
			re.Rule, err = e.BuildRule(re.Params)
			if err != nil {
				return fmt.Errorf("cannot build rule for plugin %s, name %s and params %s - error is %s", re.Plugin, re.Name, strings.Join(re.Params, ","), err)
			}
		}
	}
	return nil
}

func (p *List) ensureQueryData(ctx context.Context, name string, state request.Request, data map[string]interface{}, engines map[string]policy.Engine) (interface{}, error) {
	if d, ok := data[name]; ok {
		return d, nil
	}
	// first time this instance of enginer is triggered. Build the data
	if e, ok := engines[name]; ok {
		d, err := e.BuildQueryData(ctx, state)
		if err != nil {
			return nil, err
		}
		data[name] = d
		return d, nil
	}
	return nil, fmt.Errorf("unregistered engine instance %s", name)
}

func (p *List) ensureReplyData(ctx context.Context, name string, state request.Request, queryData interface{}, data map[string]interface{}, engines map[string]policy.Engine) (interface{}, error) {
	if d, ok := data[name]; ok {
		return d, nil
	}
	// lazy initialize.
	if e, ok := engines[name]; ok {
		d, err := e.BuildReplyData(ctx, state, queryData)
		if err != nil {
			return nil, err
		}
		data[name] = d
		return d, nil
	}
	return nil, fmt.Errorf("unregistered engine instance %s", name)
}

func (p *List) Evaluate(ctx context.Context, state request.Request, data map[string]interface{}, engines map[string]policy.Engine) (int, error) {
	// evaluate all policy one by one until one provide a valid result
	// else return the defaultPolicy value
	var dataReply = make(map[string]interface{}, 0)
	for i, r := range p.RuleList {
		rd, err := p.ensureQueryData(ctx, r.Name, state, data, engines)
		if err != nil {
			return policy.TypeNone, fmt.Errorf("rulelist rule %v, with name %s - cannot build query data for evaluation %s", i, r.Name, err)
		}
		if p.reply {
			rd, err = p.ensureReplyData(ctx, r.Name, state, rd, dataReply, engines)
			if err != nil {
				return policy.TypeNone, fmt.Errorf("rulelist rule %v, with name %s - cannot build reply data for evaluation %s", i, r.Name, err)
			}
		}
		pr, err := r.Rule.Evaluate(rd)
		if err != nil {
			return policy.TypeNone, fmt.Errorf("rulelist rule %v returned an error at evaluation %s", i, err)
		}
		if pr >= policy.TypeCount {
			return policy.TypeNone, fmt.Errorf("rulelist rule %v returned an invalid value %v", i, pr)

		}
		if pr != policy.TypeNone {
			// rule returned a valid value
			return pr, nil
		}
		// if no result just continue on next rule
	}
	// if none of rule make a statement, then we return the default policy
	return p.DefaultPolicy, nil
}
