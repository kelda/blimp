package strs

func Unique(strs []string) (unique []string) {
	strSet := map[string]struct{}{}
	for _, str := range strs {
		if _, ok := strSet[str]; ok {
			continue
		}
		strSet[str] = struct{}{}
		unique = append(unique, str)
	}
	return unique
}
