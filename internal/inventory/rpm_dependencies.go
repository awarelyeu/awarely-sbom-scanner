package inventory

import "strings"

// Rich dependency selection is conservative: retain every installed provider
// referenced by an expression. Version predicates may be true or false because
// this is an inventory collector, not an RPM transaction solver. Both possible
// conditional branches must therefore be covered before claiming completeness.
type rpmDependencyResult struct {
	ids                        map[string]bool
	covered, mayTrue, mayFalse bool
}
type rpmDependencyNode struct {
	name, op               string
	versioned              bool
	left, right, otherwise *rpmDependencyNode
}
type rpmDependencyParser struct {
	s          string
	pos, nodes int
}

func (p *rpmDependencyParser) spaces() {
	for p.pos < len(p.s) && (p.s[p.pos] == ' ' || p.s[p.pos] == '\t') {
		p.pos++
	}
}
func (p *rpmDependencyParser) word() string {
	p.spaces()
	start, parens := p.pos, 0
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		if c == ' ' || c == '\t' {
			break
		}
		if c == ')' {
			if parens == 0 {
				break
			}
			parens--
		}
		if c == '(' {
			parens++
		}
		p.pos++
	}
	if parens != 0 {
		return ""
	}
	return p.s[start:p.pos]
}
func (p *rpmDependencyParser) node(depth int) *rpmDependencyNode {
	p.spaces()
	p.nodes++
	if depth > 32 || p.nodes > 512 || p.pos >= len(p.s) {
		return nil
	}
	if p.s[p.pos] != '(' {
		name := p.word()
		if name == "" {
			return nil
		}
		n := &rpmDependencyNode{name: name}
		p.spaces()
		if p.pos < len(p.s) && strings.ContainsRune("<>=", rune(p.s[p.pos])) {
			op := p.word()
			if op != "=" && op != "<" && op != ">" && op != "<=" && op != ">=" {
				return nil
			}
			if version := p.word(); version == "" || !ValidText(version, 100) {
				return nil
			}
			n.versioned = true
		}
		return n
	}
	p.pos++
	left := p.node(depth + 1)
	if left == nil {
		return nil
	}
	op := p.word()
	if op != "and" && op != "or" && op != "if" && op != "unless" && op != "with" && op != "without" {
		return nil
	}
	right := p.node(depth + 1)
	if right == nil {
		return nil
	}
	n := &rpmDependencyNode{op: op, left: left, right: right}
	for {
		p.spaces()
		if p.pos >= len(p.s) {
			return nil
		}
		if p.s[p.pos] == ')' {
			p.pos++
			return n
		}
		next := p.word()
		if next == "else" && (op == "if" || op == "unless") && n.otherwise == nil {
			n.otherwise = p.node(depth + 1)
			if n.otherwise == nil {
				return nil
			}
			p.spaces()
			if p.pos >= len(p.s) || p.s[p.pos] != ')' {
				return nil
			}
			p.pos++
			return n
		}
		if (op != "and" && op != "or") || next != op {
			return nil
		}
		right = p.node(depth + 1)
		if right == nil {
			return nil
		}
		n = &rpmDependencyNode{op: op, left: n, right: right}
	}
}
func rpmDependency(value string, providers func(string) []string) rpmDependencyResult {
	bad := rpmDependencyResult{ids: map[string]bool{}, mayTrue: true, mayFalse: true}
	if len(value) > 4096 {
		return bad
	}
	p := rpmDependencyParser{s: value}
	n := p.node(0)
	p.spaces()
	if n == nil || p.pos != len(value) {
		return bad
	}
	var evaluate func(*rpmDependencyNode) rpmDependencyResult
	evaluate = func(n *rpmDependencyNode) rpmDependencyResult {
		r := rpmDependencyResult{ids: map[string]bool{}}
		if n.op == "" {
			if strings.HasPrefix(n.name, "rpmlib(") {
				r.covered = true
				r.mayTrue = true
				return r
			}
			for _, id := range providers(n.name) {
				r.ids[id] = true
			}
			r.covered = len(r.ids) > 0
			r.mayTrue = r.covered
			r.mayFalse = !r.covered || n.versioned
			return r
		}
		a, b := evaluate(n.left), evaluate(n.right)
		for id := range a.ids {
			r.ids[id] = true
		}
		for id := range b.ids {
			r.ids[id] = true
		}
		switch n.op {
		case "and":
			r.covered = a.covered && b.covered
			r.mayTrue = a.mayTrue && b.mayTrue
			r.mayFalse = a.mayFalse || b.mayFalse
		case "or":
			r.covered = a.covered || b.covered
			r.mayTrue = a.mayTrue || b.mayTrue
			r.mayFalse = a.mayFalse && b.mayFalse
		case "with", "without":
			for id := range a.ids {
				if b.ids[id] == (n.op == "with") {
					r.covered = true
				}
			}
			r.mayTrue = r.covered
			r.mayFalse = !r.covered || a.mayFalse || b.mayFalse
		case "if", "unless":
			c := rpmDependencyResult{covered: true, mayTrue: true}
			if n.otherwise != nil {
				c = evaluate(n.otherwise)
				for id := range c.ids {
					r.ids[id] = true
				}
			}
			takeA, takeC := b.mayTrue, b.mayFalse
			if n.op == "unless" {
				takeA, takeC = takeC, takeA
			}
			r.covered = (!takeA || a.covered) && (!takeC || c.covered)
			r.mayTrue = (takeA && a.mayTrue) || (takeC && c.mayTrue)
			r.mayFalse = (takeA && a.mayFalse) || (takeC && c.mayFalse)
		}
		return r
	}
	return evaluate(n)
}
