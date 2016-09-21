package main

import (
  "fmt"
  "github.com/alokmenghrajani/gpgeez"
)

func main() {
  config := gpgeez.Config{Expiry: 365}
  key, err := gpgeez.CreateKey("Joe", "test key", "joe@example.com", &config)
  if err != nil {
    fmt.Printf("Something went wrong: %v", err)
    return
  }
  output, err := key.Armor()
  if err != nil {
    fmt.Printf("Something went wrong: %v", err)
    return
  }
  fmt.Printf("%s\n", output)

  output, err = key.ArmorPrivate(&config)
  if err != nil {
    fmt.Printf("Something went wrong: %v", err)
    return
  }
  fmt.Printf("%s\n", output)
}
