package domain

import "time"

type User struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Display  string    `json:"display"`
	Password string    `json:"-"`
	Bio      string    `json:"bio"`
	Created  time.Time `json:"created"`
	Secret   string    `json:"-"`
}

type Post struct {
	ID      string    `json:"id"`
	Author  string    `json:"author"`
	Text    string    `json:"text"`
	Photo   string    `json:"photo"`
	Created time.Time `json:"created"`
}

type Message struct {
	ID      string    `json:"id"`
	From    string    `json:"from"`
	To      string    `json:"to"`
	Text    string    `json:"text"`
	Created time.Time `json:"created"`
}
