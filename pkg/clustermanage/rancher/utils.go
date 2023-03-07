package rancher

func mergeLabels(old, new map[string]string) map[string]string {
	m := make(map[string]string, len(old)+len(new))

	for k, v := range old {
		m[k] = v
	}
	for k, v := range new {
		m[k] = v
	}
	return m
}
