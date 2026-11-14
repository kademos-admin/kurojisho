package store

type Store struct {
	items []string
}

func New() *Store {
	return &Store{}
}

func (s *Store) Add(name string) {
	s.items = append(s.items, normalize(name))
}

func (s *Store) All() []string {
	return s.items
}

func normalize(name string) string {
	return name
}
