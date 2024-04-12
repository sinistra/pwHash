package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const (
	defaultBcryptCost = 4
	helpText          = `Usage: pwHash [action] ...arguments
	Actions:
	  hash  [password] <cost> Generate a hash with the given password and optional costs (4-31)
	  match [password] [hash] Outcome=true if correct
	  cost  [hash]            Prints the cost of the hash encryption
	
	Note: Your terminal may require the hash to be escaped. (ie wrap it in 'single quotes')`
)

type args struct {
	cmd     string
	pword   string
	hash    string
	outcome bool
	cost    int
}

func main() {
	log.Println(os.Args)
	args, err := validateArgs(os.Args)
	if err != nil {
		fmt.Println(helpText)
		log.Fatalln(err)
	}

	switch args.cmd {
	case "hash":
		log.Println("hash")
		args.hash, err = hash(args.pword, args.cost)
		if err != nil {
			log.Fatalln(err)
		}
		err = compare(args.hash, args.pword)
		if err != nil {
			log.Fatalln(err)
		}
		args.outcome = true
		fmt.Printf("outcome=%v password=%s, hash=%s\n", args.outcome, args.pword, args.hash)
	case "match":
		log.Println("match")
		err = compare(args.hash, args.pword)
		if err != nil {
			log.Fatalln(err)
		}
		args.outcome = true
		fmt.Printf("outcome=%v password=%s, hash=%s\n", args.outcome, args.pword, args.hash)
	case "cost":
		hashCost := cost(args.hash)
		args.outcome = true
		fmt.Printf("outcome=%v hash=%s cost=%d\n", args.outcome, args.hash, hashCost)
	default:
		log.Fatalln("cmd must be 'hash', 'match' or 'cost'")
	}
}

func validateArgs(input []string) (args, error) {
	var args args
	if len(input) < 3 {
		return args, errors.New("at least 2 parameters required")
	}
	args.cmd = strings.ToLower(input[1])

	switch args.cmd {
	case "hash":
		args.pword = input[2]
		if len(args.pword) < 4 {
			return args, errors.New("'password' must be at least 4 characters long")
		}
		if len(input) == 4 {
			var err error
			args.cost, err = strconv.Atoi(input[3])
			if err != nil {
				return args, err
			}
		} else {
			args.cost = defaultBcryptCost
		}
	case "match":
		args.pword = input[2]
		if len(input) < 4 {
			return args, errors.New("'match' requires a 'password' and 'hash'")
		}
		args.hash = input[3]
	case "cost":
		args.hash = input[2]
	default:
		return args, errors.New("parameter 1 must be 'hash', 'match' or 'cost'")
	}

	return args, nil
}

func hash(password string, cost int) (string, error) {
	pwHash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("could not generate bcrypt password hash: %w", err)
	}

	return string(pwHash), nil
}

func compare(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func cost(hashedPassword string) int {
	costValue, err := bcrypt.Cost([]byte(hashedPassword))
	if err != nil {
		log.Fatalln(err)
	}
	return costValue
}
