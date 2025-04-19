package middlewares

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
)

type yamlParser struct {
	indent int
}

func (p *yamlParser) Parse(value any) string {
	var sb strings.Builder
	p.parseValue(&sb, reflect.ValueOf(value), "", reflect.TypeOf(value))
	return strings.TrimSpace(sb.String())
}

func (p *yamlParser) parseValue(sb *strings.Builder, v reflect.Value, name string, t reflect.Type) {
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	switch v.Kind() {
	case reflect.Struct:
		if name != "" {
			sb.WriteString(fmt.Sprintf("%s%s:\n", strings.Repeat(" ", p.indent*2), name))
		}
		p.indent++
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			fieldValue := v.Field(i)
			fieldType := f.Type

			yamlTag := f.Tag.Get("yaml")
			defaultTag := f.Tag.Get("default")

			// Apply default value if field is empty
			if defaultTag != "" && isZeroValue(fieldValue) {
				fieldValue = reflect.ValueOf(parseDefaultValue(defaultTag, fieldType))
			}

			p.parseValue(sb, fieldValue, yamlTag, fieldType)
		}
		p.indent--
	case reflect.Slice:
		sb.WriteString(fmt.Sprintf("%s%s:\n", strings.Repeat(" ", p.indent*2), name))
		p.indent++
		for i := 0; i < v.Len(); i++ {
			sb.WriteString(fmt.Sprintf("%s- %v\n", strings.Repeat(" ", p.indent*2), v.Index(i)))
		}
		p.indent--
	default:
		if name != "" {
			sb.WriteString(fmt.Sprintf("%s%s: %v\n", strings.Repeat(" ", p.indent*2), name, v.Interface()))
		}
	}
}

// Check if a value is zero/empty
func isZeroValue(v reflect.Value) bool {
	return !v.IsValid() || reflect.DeepEqual(v.Interface(), reflect.Zero(v.Type()).Interface())
}

// Convert default string to correct type
func parseDefaultValue(defaultValue string, t reflect.Type) any {
	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		val, _ := strconv.Atoi(defaultValue)
		return val
	case reflect.Bool:
		val, _ := strconv.ParseBool(defaultValue)
		return val
	case reflect.String:
		return defaultValue
	default:
		return nil
	}
}

func MakeConfig(cfg any, Filename string) {
	f, _ := os.Create(Filename)
	defer f.Close()
	f.WriteString((&yamlParser{}).Parse(cfg))
}
