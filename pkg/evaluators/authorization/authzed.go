package authorization

import (
	gocontext "context"
	"fmt"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/json"
	"google.golang.org/grpc"
	insecuregrpc "google.golang.org/grpc/credentials/insecure"

	authzedpb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	authzed "github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
)

type Authzed struct {
	Endpoint     string
	Insecure     bool
	SharedSecret string

	Subject      json.JSONValue
	SubjectKind  json.JSONValue
	Resource     json.JSONValue
	ResourceKind json.JSONValue
	Permission   json.JSONValue
}

type permissionResponse struct {
	CheckedAt      *authzedpb.ZedToken                              `json:"checked_at,omitempty"`
	Permissionship authzedpb.CheckPermissionResponse_Permissionship `json:"permissionship,omitempty"`
}

func (a *Authzed) Call(pipeline auth.AuthPipeline, ctx gocontext.Context) (interface{}, error) {
	var dialOpts []grpc.DialOption

	if a.Insecure {
		dialOpts = append(dialOpts, grpcutil.WithInsecureBearerToken(a.SharedSecret), grpc.WithTransportCredentials(insecuregrpc.NewCredentials()))
	} else {
		systemCertsOption, _ := grpcutil.WithSystemCerts(grpcutil.VerifyCA)
		dialOpts = append(dialOpts, grpcutil.WithBearerToken(a.SharedSecret), systemCertsOption)
	}

	client, err := authzed.NewClient(a.Endpoint, dialOpts...)
	if err != nil {
		return nil, err
	}

	authJSON := pipeline.GetAuthorizationJSON()

	resp, err := client.CheckPermission(ctx, &authzedpb.CheckPermissionRequest{
		Resource:   authzedObjectFor(a.Resource, a.ResourceKind, authJSON),
		Subject:    &authzedpb.SubjectReference{Object: authzedObjectFor(a.Subject, a.SubjectKind, authJSON)},
		Permission: fmt.Sprintf("%s", a.Permission.ResolveFor(authJSON)),
	})
	if err != nil {
		return nil, err
	}

	if resp.Permissionship != authzedpb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION {
		var token string
		if checkedAt := resp.CheckedAt; checkedAt != nil {
			token = fmt.Sprintf(";token=%s", checkedAt.Token)
		}
		return nil, fmt.Errorf("%s%s", resp.Permissionship, token)
	}

	// convert to our own PermissionResponse type - hack to avoid the object being stringified in the authorzation JSON
	obj := &permissionResponse{
		CheckedAt:      resp.GetCheckedAt(),
		Permissionship: resp.GetPermissionship(),
	}

	return obj, nil
}

func authzedObjectFor(name, kind json.JSONValue, authJSON string) *authzedpb.ObjectReference {
	return &authzedpb.ObjectReference{
		ObjectId:   fmt.Sprintf("%s", name.ResolveFor(authJSON)),
		ObjectType: fmt.Sprintf("%s", kind.ResolveFor(authJSON)),
	}
}
