package authorization

import (
	gocontext "context"
	"fmt"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/expressions"
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

	Subject      expressions.Value
	SubjectKind  expressions.Value
	Resource     expressions.Value
	ResourceKind expressions.Value
	Permission   expressions.Value
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

	resource, err := authzedObjectFor(a.Resource, a.ResourceKind, authJSON)
	if err != nil {
		return nil, err
	}
	object, err := authzedObjectFor(a.Subject, a.SubjectKind, authJSON)
	if err != nil {
		return nil, err
	}
	permission, err := a.Permission.ResolveFor(authJSON)
	if err != nil {
		return nil, err
	}
	permissionStr, err := json.StringifyJSON(permission)
	if err != nil {
		return nil, err
	}
	resp, err := client.CheckPermission(ctx, &authzedpb.CheckPermissionRequest{
		Resource:   resource,
		Subject:    &authzedpb.SubjectReference{Object: object},
		Permission: permissionStr,
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

func authzedObjectFor(name, kind expressions.Value, authJSON string) (*authzedpb.ObjectReference, error) {
	objectId, err := name.ResolveFor(authJSON)
	if err != nil {
		return nil, err
	}
	objectIdStr, err := json.StringifyJSON(objectId)
	if err != nil {
		return nil, err
	}
	objectType, err := kind.ResolveFor(authJSON)
	if err != nil {
		return nil, err
	}
	objectTypeStr, err := json.StringifyJSON(objectType)
	if err != nil {
		return nil, err
	}
	return &authzedpb.ObjectReference{
		ObjectId:   objectIdStr,
		ObjectType: objectTypeStr,
	}, nil
}
