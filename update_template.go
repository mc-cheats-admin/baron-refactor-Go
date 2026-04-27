package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	content, err := ioutil.ReadFile("internal/service/builder.go")
	if err != nil {
		log.Fatal(err)
	}

	templateStart := []byte("const csharpTemplate = `\n")
	idx := bytes.Index(content, templateStart)
	if idx == -1 {
		log.Fatal("Could not find template start")
	}

	// Find the end of the template
	endIdx := bytes.Index(content[idx+len(templateStart):], []byte("`"))
	if endIdx == -1 {
		log.Fatal("Could not find template end")
	}
	endIdx += idx + len(templateStart)

	newTemplate, err := ioutil.ReadFile("new_template.cs")
	if err != nil {
		log.Fatal(err)
	}

	var newContent bytes.Buffer
	newContent.Write(content[:idx])
	newContent.WriteString("const csharpTemplate = `\n")
	newContent.Write(newTemplate)
	newContent.WriteString("`\n")
	newContent.Write(content[endIdx+1:])

	err = ioutil.WriteFile("internal/service/builder.go", newContent.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Successfully updated builder.go")
}
