package yesdns

type ResolverListener struct {
	Net 			string	`json:"net"`
	Address			string	`json:"address"`
}

func (rl ResolverListener) Key() string {
	return rl.Address + "-" + rl.Net
}