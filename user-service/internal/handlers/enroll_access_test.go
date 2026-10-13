package handlers

import (
	"net/http"
	"testing"

	"github.com/genesary/pupitre/user-service/fake"
	"github.com/genesary/pupitre/user-service/internal/config"
)

// TestEnroll_AccessControl verifies that self-service enrollment only
// succeeds for an existing, public course (or an admin), and never creates
// a row for a private, non-existent, or malformed slug. This is the
// regression guard for the self-enroll access-control bug.
func TestEnroll_AccessControl(t *testing.T) {
	t.Parallel()

	courseSvc, _ := newCatalogServer(t, catalogFixture{Courses: map[string]CourseInfo{
		"public-course":  {Slug: "public-course", ID: "public-course", Title: "Public", IsPublic: true},
		"private-course": {Slug: "private-course", ID: "private-course", Title: "Private", IsPublic: false},
	}})

	cases := []struct {
		name       string
		slug       string
		role       string
		wantStatus int
		wantRow    bool
	}{
		{"public course enrolls", "public-course", "student", http.StatusOK, true},
		{"private course rejected", "private-course", "student", http.StatusForbidden, false},
		{"nonexistent slug rejected", "does-not-exist", "student", http.StatusNotFound, false},
		{"malformed slug rejected", "Invalid_Slug", "student", http.StatusBadRequest, false},
		{"admin may enroll in private", "private-course", "admin", http.StatusOK, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enr := fake.NewEnrollmentRepository()
			repos := fake.NewRepositories()
			repos.Enrollments = enr

			s := &State{Repos: repos, Config: &config.Config{
				JWTSecret: htSecret, JWTExpiryH: htExpiry, CORSOrigins: []string{"*"},
				CourseServiceURL: courseSvc.URL,
			}}
			r := BuildRouter(s, s.Config, false)

			rec := htDo(t, r, http.MethodPost, "/api/enrollments/"+tc.slug, "{}", htAuthHeader(t, tc.role))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}

			got, _ := enr.Exists(t.Context(), "user-uuid-1", tc.slug)
			if got != tc.wantRow {
				t.Fatalf("enrollment row present = %v, want %v", got, tc.wantRow)
			}
		})
	}
}
