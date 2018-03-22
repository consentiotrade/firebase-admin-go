// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package snippets

import (
	"fmt"
	"log"

	"golang.org/x/net/context"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/links"
)

func testLinkStats(ctx context.Context, app *firebase.App) {
	// [START get_link_stats]
	client, err := app.DynamicLinks(ctx)
	if err != nil {
		log.Fatalln(err)
	}
	stats, err := client.LinkStats(ctx, "https://abc.app.goo.gl/abc12",
		links.StatOptions{LastNDays: 7})
	if err != nil {
		log.Fatalln(err)
	}
	for _, stat := range stats.EventStats {
		if stat.Platform == links.Android && stat.EventType == links.Click {
			fmt.Printf("There were %v clicks on Android in the last 7 days", stat.Count)
		}
	}
	// [END get_link_stats]
}