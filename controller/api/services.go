package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jc-lab/suricontroller/controller/auth"
	"github.com/jc-lab/suricontroller/controller/configrepo"
	"github.com/jc-lab/suricontroller/controller/deploy"
	"github.com/jc-lab/suricontroller/controller/gitrepo"
	"github.com/jc-lab/suricontroller/controller/logs"
	"github.com/jc-lab/suricontroller/controller/rules"
	"github.com/jc-lab/suricontroller/controller/store"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	apiv1 "github.com/jc-lab/suricontroller/gen/suricontroller/api/v1"
)

var nowFunc = time.Now

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func principalProto(p *auth.Principal) *apiv1.Principal {
	if p == nil {
		return nil
	}
	return &apiv1.Principal{Id: p.ID, DisplayName: p.DisplayName, Roles: p.Roles}
}

// --- AuthService -------------------------------------------------------------

type authService struct{ s *Server }

func (a *authService) GetAuthInfo(ctx context.Context, _ *connect.Request[apiv1.GetAuthInfoRequest]) (*connect.Response[apiv1.GetAuthInfoResponse], error) {
	resp := &apiv1.GetAuthInfoResponse{Principal: principalProto(auth.FromContext(ctx))}
	if _, ok := a.s.Auth.(auth.PasswordLogin); ok {
		resp.PasswordLogin = true
	}
	if ext, ok := a.s.Auth.(auth.ExternalLogin); ok {
		resp.LoginUrl = ext.LoginURL("")
	}
	return connect.NewResponse(resp), nil
}

func (a *authService) Login(ctx context.Context, req *connect.Request[apiv1.LoginRequest]) (*connect.Response[apiv1.LoginResponse], error) {
	pl, ok := a.s.Auth.(auth.PasswordLogin)
	if !ok {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("password login is not supported"))
	}
	p, err := pl.Login(ctx, req.Msg.Username, req.Msg.Password)
	if err != nil {
		user := req.Msg.Username
		if len(user) > 64 {
			user = user[:64] + "..."
		}
		a.s.Logger.Warn("login failed", "user", user, "client", req.Peer().Addr)
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, connect.NewError(connect.CodeUnauthenticated, err)
		}
		return nil, connect.NewError(connect.CodeResourceExhausted, err)
	}
	resp := connect.NewResponse(&apiv1.LoginResponse{Principal: principalProto(p)})
	if si, ok := a.s.Auth.(auth.SessionIssuer); ok {
		if err := si.IssueSession(resp.Header(), p); err != nil {
			return nil, toConnectError(err)
		}
	}
	a.s.audit(auth.WithPrincipal(ctx, p), "login", p.ID, "")
	return resp, nil
}

func (a *authService) Logout(_ context.Context, _ *connect.Request[apiv1.LogoutRequest]) (*connect.Response[apiv1.LogoutResponse], error) {
	resp := connect.NewResponse(&apiv1.LogoutResponse{})
	if si, ok := a.s.Auth.(auth.SessionIssuer); ok {
		si.ClearSession(resp.Header())
	}
	return resp, nil
}

// --- SystemService -----------------------------------------------------------

type systemService struct{ s *Server }

func (y *systemService) GetInfo(context.Context, *connect.Request[apiv1.GetInfoRequest]) (*connect.Response[apiv1.GetInfoResponse], error) {
	return connect.NewResponse(&apiv1.GetInfoResponse{
		Version:            y.s.Version,
		HostKey:            y.s.HostKey.String(),
		HostKeyFingerprint: y.s.HostKey.Fingerprint(),
		AgentPath:          y.s.AgentPath,
	}), nil
}

func (y *systemService) settings() *apiv1.Settings {
	return &apiv1.Settings{LogIngestQueueMaxBytes: uint64(y.s.Logs.QueueCapacity())}
}

func (y *systemService) GetSettings(context.Context, *connect.Request[apiv1.GetSettingsRequest]) (*connect.Response[apiv1.GetSettingsResponse], error) {
	return connect.NewResponse(&apiv1.GetSettingsResponse{Settings: y.settings()}), nil
}

func (y *systemService) UpdateSettings(ctx context.Context, req *connect.Request[apiv1.UpdateSettingsRequest]) (*connect.Response[apiv1.UpdateSettingsResponse], error) {
	st := req.Msg.Settings
	if st == nil {
		return nil, invalid("settings are required")
	}
	if st.LogIngestQueueMaxBytes > 0 {
		if err := y.s.Logs.SetQueueCapacity(ctx, int64(st.LogIngestQueueMaxBytes)); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}
	y.s.audit(ctx, "settings.update", "system", fmt.Sprintf("log_ingest_queue_max_bytes=%d", st.LogIngestQueueMaxBytes))
	return connect.NewResponse(&apiv1.UpdateSettingsResponse{Settings: y.settings()}), nil
}

// --- NodeService -------------------------------------------------------------

type nodeService struct{ s *Server }

func (ns *nodeService) view(n *store.Node) *apiv1.Node {
	s := ns.s
	v := &apiv1.Node{
		Id:           n.ID,
		PublicKey:    n.PublicKey,
		Fingerprint:  n.Fingerprint,
		Enabled:      n.Enabled,
		Description:  n.Description,
		CreatedAt:    ts(n.CreatedAt),
		LastSeenAt:   ts(n.LastSeenAt),
		AgentVersion: n.Hello.GetAgentVersion(),
		Platform:     n.Hello.GetPlatform(),
		Engine:       n.Hello.GetEngine(),
		Warnings:     n.Hello.GetWarnings(),
		LogSources:   n.Hello.GetLogSources(),
	}
	interfaces := n.Hello.GetInterfaces()
	if sess := s.Gateway.Session(n.ID); sess != nil {
		v.Online = true
		v.ConnectedAt = ts(sess.ConnectedAt)
		v.RemoteAddr = sess.RemoteAddr
		v.LastSeenAt = ts(nowFunc())
		if st := s.Nodes.Status(n.ID); st != nil {
			v.Instances = st.Instances
			v.LogQueue = st.LogQueue
			if len(st.Warnings) > 0 {
				v.Warnings = st.Warnings
			}
			if len(st.LogSources) > 0 {
				v.LogSources = st.LogSources
			}
			if len(st.Interfaces) > 0 {
				interfaces = st.Interfaces
			}
		}
	}
	for _, ifc := range interfaces {
		mode := n.InterfaceModes[ifc.Name]
		if mode == agentv1.InterfaceMode_INTERFACE_MODE_UNSPECIFIED {
			mode = agentv1.InterfaceMode_INTERFACE_MODE_OFF
		}
		applied := n.Applied.GetInterfaceModes()[ifc.Name]
		if applied == agentv1.InterfaceMode_INTERFACE_MODE_UNSPECIFIED {
			applied = agentv1.InterfaceMode_INTERFACE_MODE_OFF
		}
		v.Interfaces = append(v.Interfaces, &apiv1.NodeInterface{
			Name: ifc.Name, IpsAllowed: ifc.IpsAllowed, Present: ifc.Present, Up: ifc.Up, Addresses: ifc.Addresses,
			Mode: mode, AppliedMode: applied,
		})
	}
	if ti := n.Hello.GetTap(); ti != nil {
		tap := &apiv1.NodeTap{Enabled: ti.Enabled, SocketDir: ti.SocketDir, PluginPresent: ti.PluginPresent}
		for _, ep := range ti.Endpoints {
			mode := n.EndpointModes[ep.Name]
			if mode == agentv1.EndpointMode_ENDPOINT_MODE_UNSPECIFIED {
				mode = agentv1.EndpointMode_ENDPOINT_MODE_OFF
			}
			applied := n.Applied.GetEndpointModes()[ep.Name]
			if applied == agentv1.EndpointMode_ENDPOINT_MODE_UNSPECIFIED {
				applied = agentv1.EndpointMode_ENDPOINT_MODE_OFF
			}
			tap.Endpoints = append(tap.Endpoints, &apiv1.NodeTapEndpoint{
				Name: ep.Name, PreventAllowed: ep.PreventAllowed, Description: ep.Description, Mode: mode, AppliedMode: applied,
			})
		}
		v.Tap = tap
	}
	d := &apiv1.NodeDeployState{
		DesiredGeneration: n.Desired.GetGeneration(),
		DesiredBundle:     n.Desired.GetBundle(),
		AppliedGeneration: n.Applied.GetGeneration(),
		AppliedBundle:     n.Applied.GetBundle(),
		LastStatus:        n.LastReport.GetStatus(),
		LastStage:         n.LastReport.GetStage(),
		LastMessage:       n.LastReport.GetMessage(),
		LastReportAt:      ts(n.LastReportAt),
		DesiredError:      n.DesiredError,
	}
	d.InSync = n.Desired != nil && n.Applied != nil && n.Applied.Generation == n.Desired.Generation
	v.Deploy = d
	return v
}

func (ns *nodeService) ListNodes(ctx context.Context, _ *connect.Request[apiv1.ListNodesRequest]) (*connect.Response[apiv1.ListNodesResponse], error) {
	list, err := ns.s.Nodes.List(ctx)
	if err != nil {
		return nil, toConnectError(err)
	}
	resp := &apiv1.ListNodesResponse{}
	for _, n := range list {
		resp.Nodes = append(resp.Nodes, ns.view(n))
	}
	return connect.NewResponse(resp), nil
}

func (ns *nodeService) GetNode(ctx context.Context, req *connect.Request[apiv1.GetNodeRequest]) (*connect.Response[apiv1.GetNodeResponse], error) {
	n, err := ns.s.Nodes.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.GetNodeResponse{Node: ns.view(n)}), nil
}

func (ns *nodeService) AddNode(ctx context.Context, req *connect.Request[apiv1.AddNodeRequest]) (*connect.Response[apiv1.AddNodeResponse], error) {
	n, err := ns.s.Nodes.Add(ctx, req.Msg.PublicKey, req.Msg.Description)
	if err != nil {
		return nil, toConnectError(err)
	}
	ns.s.audit(ctx, "node.add", n.ID, n.Fingerprint)
	return connect.NewResponse(&apiv1.AddNodeResponse{Node: ns.view(n)}), nil
}

func (ns *nodeService) UpdateNode(ctx context.Context, req *connect.Request[apiv1.UpdateNodeRequest]) (*connect.Response[apiv1.UpdateNodeResponse], error) {
	n, err := ns.s.Nodes.Update(ctx, req.Msg.Id, req.Msg.Enabled, req.Msg.Description)
	if err != nil {
		return nil, toConnectError(err)
	}
	ns.s.audit(ctx, "node.update", n.ID, fmt.Sprintf("enabled=%v", n.Enabled))
	return connect.NewResponse(&apiv1.UpdateNodeResponse{Node: ns.view(n)}), nil
}

func (ns *nodeService) DeleteNode(ctx context.Context, req *connect.Request[apiv1.DeleteNodeRequest]) (*connect.Response[apiv1.DeleteNodeResponse], error) {
	if err := ns.s.Nodes.Delete(ctx, req.Msg.Id); err != nil {
		return nil, toConnectError(err)
	}
	ns.s.Gateway.Disconnect(req.Msg.Id)
	ns.s.audit(ctx, "node.delete", req.Msg.Id, "")
	return connect.NewResponse(&apiv1.DeleteNodeResponse{}), nil
}

func (ns *nodeService) SetInterfaceModes(ctx context.Context, req *connect.Request[apiv1.SetInterfaceModesRequest]) (*connect.Response[apiv1.SetInterfaceModesResponse], error) {
	n, err := ns.s.Nodes.SetInterfaceModes(ctx, req.Msg.Id, req.Msg.Modes)
	if err != nil {
		return nil, toConnectError(err)
	}
	var parts []string
	for k, v := range req.Msg.Modes {
		parts = append(parts, k+"="+strings.TrimPrefix(v.String(), "INTERFACE_MODE_"))
	}
	ns.s.audit(ctx, "node.interfaces", n.ID, strings.Join(parts, ","))
	return connect.NewResponse(&apiv1.SetInterfaceModesResponse{Node: ns.view(n)}), nil
}

func (ns *nodeService) SetEndpointModes(ctx context.Context, req *connect.Request[apiv1.SetEndpointModesRequest]) (*connect.Response[apiv1.SetEndpointModesResponse], error) {
	n, err := ns.s.Nodes.SetEndpointModes(ctx, req.Msg.Id, req.Msg.Modes)
	if err != nil {
		return nil, toConnectError(err)
	}
	var parts []string
	for k, v := range req.Msg.Modes {
		parts = append(parts, k+"="+strings.TrimPrefix(v.String(), "ENDPOINT_MODE_"))
	}
	sort.Strings(parts)
	ns.s.audit(ctx, "node.tap_endpoints", n.ID, strings.Join(parts, ","))
	return connect.NewResponse(&apiv1.SetEndpointModesResponse{Node: ns.view(n)}), nil
}

func (ns *nodeService) ListApplyHistory(ctx context.Context, req *connect.Request[apiv1.ListApplyHistoryRequest]) (*connect.Response[apiv1.ListApplyHistoryResponse], error) {
	entries, err := ns.s.Store.ListApplyHistory(ctx, req.Msg.Id, int(req.Msg.Limit))
	if err != nil {
		return nil, toConnectError(err)
	}
	resp := &apiv1.ListApplyHistoryResponse{}
	for _, e := range entries {
		resp.Entries = append(resp.Entries, &apiv1.ApplyHistoryEntry{Id: e.ID, Report: e.Report, CreatedAt: ts(e.CreatedAt)})
	}
	return connect.NewResponse(resp), nil
}

// --- RepoService -------------------------------------------------------------

type repoService struct{ s *Server }

func (rs *repoService) repo(r apiv1.Repo) (*gitrepo.Repo, string, error) {
	switch r {
	case apiv1.Repo_REPO_RULES:
		return rs.s.RulesRepo, deploy.KindRules, nil
	case apiv1.Repo_REPO_CONFIG:
		return rs.s.ConfigRepo, deploy.KindConfig, nil
	}
	return nil, "", invalid("repo must be REPO_RULES or REPO_CONFIG")
}

func commitProto(c *gitrepo.CommitInfo) *apiv1.Commit {
	return &apiv1.Commit{Id: c.ID, Message: c.Message, Author: c.Author, Time: ts(c.Time), Parents: c.Parents}
}

func statsProto(stats []gitrepo.FileStat) []*apiv1.FileChangeStat {
	var out []*apiv1.FileChangeStat
	for _, st := range stats {
		out = append(out, &apiv1.FileChangeStat{Path: st.Path, Action: st.Action, Additions: uint32(st.Additions), Deletions: uint32(st.Deletions)})
	}
	return out
}

func (rs *repoService) ListCommits(_ context.Context, req *connect.Request[apiv1.ListCommitsRequest]) (*connect.Response[apiv1.ListCommitsResponse], error) {
	repo, _, err := rs.repo(req.Msg.Repo)
	if err != nil {
		return nil, err
	}
	limit := int(req.Msg.Limit)
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	from := ""
	if req.Msg.Before != "" {
		_, _, err := repo.GetCommit(req.Msg.Before)
		if err != nil {
			return nil, toConnectError(err)
		}
		// Fetch one extra and drop the "before" commit itself.
		from = req.Msg.Before
		limit++
	}
	list, err := repo.Log(from, limit, req.Msg.Path)
	if err != nil {
		return nil, toConnectError(err)
	}
	head, _ := repo.Head()
	resp := &apiv1.ListCommitsResponse{Head: head}
	for i := range list {
		if from != "" && i == 0 {
			continue
		}
		resp.Commits = append(resp.Commits, commitProto(&list[i]))
	}
	return connect.NewResponse(resp), nil
}

func (rs *repoService) GetCommit(_ context.Context, req *connect.Request[apiv1.GetCommitRequest]) (*connect.Response[apiv1.GetCommitResponse], error) {
	repo, _, err := rs.repo(req.Msg.Repo)
	if err != nil {
		return nil, err
	}
	c, stats, err := repo.GetCommit(req.Msg.Id)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.GetCommitResponse{Commit: commitProto(c), Files: statsProto(stats)}), nil
}

func (rs *repoService) ListTree(_ context.Context, req *connect.Request[apiv1.ListTreeRequest]) (*connect.Response[apiv1.ListTreeResponse], error) {
	repo, _, err := rs.repo(req.Msg.Repo)
	if err != nil {
		return nil, err
	}
	commit, err := repo.Resolve(req.Msg.Commit)
	if errors.Is(err, gitrepo.ErrNotFound) && req.Msg.Commit == "" {
		return connect.NewResponse(&apiv1.ListTreeResponse{}), nil
	}
	if err != nil {
		return nil, toConnectError(err)
	}
	entries, err := repo.ListTree(commit, req.Msg.Path, req.Msg.Recursive)
	if err != nil {
		return nil, toConnectError(err)
	}
	resp := &apiv1.ListTreeResponse{Commit: commit}
	for _, e := range entries {
		resp.Entries = append(resp.Entries, &apiv1.TreeEntry{Path: e.Path, Dir: e.Dir, Size: uint64(e.Size)})
	}
	return connect.NewResponse(resp), nil
}

func (rs *repoService) ReadFile(_ context.Context, req *connect.Request[apiv1.ReadFileRequest]) (*connect.Response[apiv1.ReadFileResponse], error) {
	repo, _, err := rs.repo(req.Msg.Repo)
	if err != nil {
		return nil, err
	}
	commit, err := repo.Resolve(req.Msg.Commit)
	if err != nil {
		return nil, toConnectError(err)
	}
	b, err := repo.ReadFile(commit, req.Msg.Path)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.ReadFileResponse{Commit: commit, Content: b}), nil
}

func (rs *repoService) WriteFiles(ctx context.Context, req *connect.Request[apiv1.WriteFilesRequest]) (*connect.Response[apiv1.WriteFilesResponse], error) {
	repo, kind, err := rs.repo(req.Msg.Repo)
	if err != nil {
		return nil, err
	}
	if len(req.Msg.Changes) == 0 {
		return nil, invalid("no changes")
	}
	msg := strings.TrimSpace(req.Msg.Message)
	if msg == "" {
		return nil, invalid("commit message is required")
	}
	var changes []gitrepo.Change
	var paths []string
	for _, c := range req.Msg.Changes {
		p, err := gitrepo.CleanPath(c.Path)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid path %q", c.Path))
		}
		if err := rs.checkWritable(ctx, kind, p, c); err != nil {
			return nil, err
		}
		changes = append(changes, gitrepo.Change{Path: p, Content: c.Content, Delete: c.Delete})
		paths = append(paths, p)
	}
	p := auth.FromContext(ctx)
	commit, err := repo.Commit(req.Msg.BaseCommit, changes, msg, gitrepo.Signature{Name: p.Name(), Email: p.ID + "@suricontroller.local"})
	if err != nil {
		return nil, toConnectError(err)
	}
	rs.s.audit(ctx, "repo.commit", kind, commit+" "+strings.Join(paths, ","))
	if err := rs.s.Deploy.OnCommit(ctx, kind); err != nil {
		rs.s.Logger.Error("deploy on commit", "err", err)
	}
	info, _, err := repo.GetCommit(commit)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.WriteFilesResponse{Commit: commitProto(info)}), nil
}

func (rs *repoService) checkWritable(ctx context.Context, kind, p string, c *apiv1.FileChange) error {
	switch kind {
	case deploy.KindConfig:
		var err error
		if c.Delete {
			err = configrepo.ValidatePath(p)
		} else {
			err = configrepo.ValidateFile(p, c.Content, rs.s.ConfValidator)
		}
		if err != nil {
			return connect.NewError(connect.CodeInvalidArgument, err)
		}
	case deploy.KindRules:
		first, rest, ok := strings.Cut(p, "/")
		if !ok || rest == "" {
			return invalid("rule files must be inside a provider directory")
		}
		pr, err := rs.s.Store.GetProvider(ctx, first)
		if errors.Is(err, store.ErrNotFound) {
			return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("unknown provider %q", first))
		}
		if err != nil {
			return toConnectError(err)
		}
		if rs.s.Rules.Fetches(pr.Type) {
			return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("provider %q is downloaded automatically and cannot be edited", first))
		}
		if !c.Delete && path.Ext(p) != ".rules" && !strings.HasSuffix(p, ".config") {
			return invalid("only .rules and .config files are allowed")
		}
	}
	return nil
}

func (rs *repoService) Diff(_ context.Context, req *connect.Request[apiv1.DiffRequest]) (*connect.Response[apiv1.DiffResponse], error) {
	repo, _, err := rs.repo(req.Msg.Repo)
	if err != nil {
		return nil, err
	}
	patch, stats, truncated, err := repo.Diff(req.Msg.From, req.Msg.To, req.Msg.Path, 0)
	if err != nil {
		return nil, toConnectError(err)
	}
	patch = strings.ToValidUTF8(patch, "\uFFFD")
	if truncated {
		patch += "\n... diff truncated ...\n"
	}
	return connect.NewResponse(&apiv1.DiffResponse{UnifiedDiff: patch, Files: statsProto(stats)}), nil
}

// --- RuleService -------------------------------------------------------------

type ruleService struct{ s *Server }

func (r *ruleService) providerProto(p *store.Provider) *apiv1.Provider {
	return &apiv1.Provider{
		Name: p.Name, Type: p.Type, Enabled: p.Enabled, IntervalSeconds: uint32(p.Interval / time.Second),
		Options: p.Options, LastFetchAt: ts(p.LastFetchAt), LastSuccessAt: ts(p.LastSuccessAt),
		LastError: p.LastError, LastCommit: p.LastCommit, Fetches: r.s.Rules.Fetches(p.Type),
	}
}

func (r *ruleService) ListProviders(ctx context.Context, _ *connect.Request[apiv1.ListProvidersRequest]) (*connect.Response[apiv1.ListProvidersResponse], error) {
	list, err := r.s.Rules.List(ctx)
	if err != nil {
		return nil, toConnectError(err)
	}
	resp := &apiv1.ListProvidersResponse{}
	for _, p := range list {
		resp.Providers = append(resp.Providers, r.providerProto(p))
	}
	return connect.NewResponse(resp), nil
}

func (r *ruleService) UpdateProvider(ctx context.Context, req *connect.Request[apiv1.UpdateProviderRequest]) (*connect.Response[apiv1.UpdateProviderResponse], error) {
	var interval *time.Duration
	if req.Msg.IntervalSeconds != nil {
		d := time.Duration(*req.Msg.IntervalSeconds) * time.Second
		interval = &d
	}
	p, err := r.s.Rules.Update(ctx, req.Msg.Name, req.Msg.Enabled, interval, req.Msg.Options)
	if err != nil {
		if errors.Is(err, rules.ErrUnknownProvider) {
			return nil, toConnectError(err)
		}
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	r.s.audit(ctx, "provider.update", p.Name, fmt.Sprintf("enabled=%v interval=%s", p.Enabled, p.Interval))
	return connect.NewResponse(&apiv1.UpdateProviderResponse{Provider: r.providerProto(p)}), nil
}

func (r *ruleService) SyncProvider(ctx context.Context, req *connect.Request[apiv1.SyncProviderRequest]) (*connect.Response[apiv1.SyncProviderResponse], error) {
	commit, err := r.s.Rules.Sync(ctx, req.Msg.Name)
	resp := &apiv1.SyncProviderResponse{Changed: commit != "", Commit: commit}
	if p, perr := r.s.Store.GetProvider(ctx, req.Msg.Name); perr == nil {
		resp.Provider = r.providerProto(p)
	}
	if err != nil {
		if errors.Is(err, rules.ErrUnknownProvider) || errors.Is(err, store.ErrNotFound) {
			return nil, toConnectError(err)
		}
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	r.s.audit(ctx, "provider.sync", req.Msg.Name, commit)
	return connect.NewResponse(resp), nil
}

// --- DeployService -----------------------------------------------------------

type deployService struct{ s *Server }

func kindOf(k apiv1.DeployKind) (string, error) {
	switch k {
	case apiv1.DeployKind_DEPLOY_KIND_RULES:
		return deploy.KindRules, nil
	case apiv1.DeployKind_DEPLOY_KIND_CONFIG:
		return deploy.KindConfig, nil
	}
	return "", invalid("kind must be DEPLOY_KIND_RULES or DEPLOY_KIND_CONFIG")
}

func modeProto(m string) apiv1.DeployMode {
	switch m {
	case deploy.ModeAuto:
		return apiv1.DeployMode_DEPLOY_MODE_AUTO
	case deploy.ModePinned:
		return apiv1.DeployMode_DEPLOY_MODE_PINNED
	case deploy.ModePaused:
		return apiv1.DeployMode_DEPLOY_MODE_PAUSED
	}
	return apiv1.DeployMode_DEPLOY_MODE_UNSPECIFIED
}

func (d *deployService) policy(ctx context.Context, kind string, k apiv1.DeployKind) (*apiv1.DeployPolicy, error) {
	p, head, err := d.s.Deploy.Policy(ctx, kind)
	if err != nil {
		return nil, err
	}
	return &apiv1.DeployPolicy{
		Kind: k, Mode: modeProto(p.Mode), PinnedCommit: p.PinnedCommit, EffectiveCommit: p.EffectiveCommit,
		HeadCommit: head, UpdatedAt: ts(p.UpdatedAt), UpdatedBy: p.UpdatedBy,
	}, nil
}

func (d *deployService) GetPolicies(ctx context.Context, _ *connect.Request[apiv1.GetPoliciesRequest]) (*connect.Response[apiv1.GetPoliciesResponse], error) {
	r, err := d.policy(ctx, deploy.KindRules, apiv1.DeployKind_DEPLOY_KIND_RULES)
	if err != nil {
		return nil, toConnectError(err)
	}
	c, err := d.policy(ctx, deploy.KindConfig, apiv1.DeployKind_DEPLOY_KIND_CONFIG)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.GetPoliciesResponse{Rules: r, Config: c}), nil
}

func (d *deployService) SetPolicy(ctx context.Context, req *connect.Request[apiv1.SetPolicyRequest]) (*connect.Response[apiv1.SetPolicyResponse], error) {
	kind, err := kindOf(req.Msg.Kind)
	if err != nil {
		return nil, err
	}
	var mode string
	switch req.Msg.Mode {
	case apiv1.DeployMode_DEPLOY_MODE_AUTO:
		mode = deploy.ModeAuto
	case apiv1.DeployMode_DEPLOY_MODE_PINNED:
		mode = deploy.ModePinned
	case apiv1.DeployMode_DEPLOY_MODE_PAUSED:
		mode = deploy.ModePaused
	default:
		return nil, invalid("invalid mode")
	}
	if _, err := d.s.Deploy.SetPolicy(ctx, kind, mode, req.Msg.PinnedCommit, auth.FromContext(ctx).Name()); err != nil {
		return nil, toConnectError(err)
	}
	d.s.audit(ctx, "deploy.policy", kind, mode+" "+req.Msg.PinnedCommit)
	p, err := d.policy(ctx, kind, req.Msg.Kind)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.SetPolicyResponse{Policy: p}), nil
}

func (d *deployService) PreviewNode(ctx context.Context, req *connect.Request[apiv1.PreviewNodeRequest]) (*connect.Response[apiv1.PreviewNodeResponse], error) {
	if _, err := d.s.Nodes.Get(ctx, req.Msg.NodeId); err != nil {
		return nil, toConnectError(err)
	}
	res, err := d.s.Deploy.Preview(ctx, req.Msg.NodeId, req.Msg.RulesCommit, req.Msg.ConfigCommit)
	if err != nil {
		if errors.Is(err, deploy.ErrInvalidArgument) {
			return nil, toConnectError(err)
		}
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	st := res.Manifest.RuleStats
	return connect.NewResponse(&apiv1.PreviewNodeResponse{
		RulesCommit: res.RulesCommit, ConfigCommit: res.ConfigCommit, BundleId: res.ID, BundleSize: uint64(res.Size),
		RuleStats: &apiv1.RuleStats{
			Total: uint32(st.Total), Enabled: uint32(st.Enabled), Disabled: uint32(st.Disabled),
			Dropped: uint32(st.Dropped), Modified: uint32(st.Modified), FlowbitsEnabled: uint32(st.FlowbitsEnabled),
		},
		ControllerYaml: string(res.ControllerYAML),
		Warnings:       res.Warnings,
	}), nil
}

// --- LogService --------------------------------------------------------------

type logService struct{ s *Server }

func (l *logService) GetCollectionPolicies(ctx context.Context, _ *connect.Request[apiv1.GetCollectionPoliciesRequest]) (*connect.Response[apiv1.GetCollectionPoliciesResponse], error) {
	global, err := l.s.Logs.GlobalPolicy(ctx)
	if err != nil {
		return nil, toConnectError(err)
	}
	list, err := l.s.Nodes.List(ctx)
	if err != nil {
		return nil, toConnectError(err)
	}
	resp := &apiv1.GetCollectionPoliciesResponse{Global: global, Nodes: map[string]*agentv1.LogCollectionPolicy{}}
	for _, n := range list {
		if n.LogPolicy != nil {
			resp.Nodes[n.ID] = n.LogPolicy
		}
	}
	return connect.NewResponse(resp), nil
}

func validatePolicy(p *agentv1.LogCollectionPolicy) error {
	if p == nil {
		return invalid("policy is required")
	}
	for _, t := range p.Types {
		if !logTypeValid(t) {
			return invalid("invalid log type " + t.String())
		}
	}
	return nil
}

func (l *logService) SetGlobalCollectionPolicy(ctx context.Context, req *connect.Request[apiv1.SetGlobalCollectionPolicyRequest]) (*connect.Response[apiv1.SetGlobalCollectionPolicyResponse], error) {
	if err := validatePolicy(req.Msg.Policy); err != nil {
		return nil, err
	}
	if err := l.s.Logs.SetGlobalPolicy(ctx, req.Msg.Policy); err != nil {
		return nil, toConnectError(err)
	}
	l.s.audit(ctx, "logs.policy", "global", req.Msg.Policy.String())
	return connect.NewResponse(&apiv1.SetGlobalCollectionPolicyResponse{}), nil
}

func (l *logService) SetNodeCollectionPolicy(ctx context.Context, req *connect.Request[apiv1.SetNodeCollectionPolicyRequest]) (*connect.Response[apiv1.SetNodeCollectionPolicyResponse], error) {
	var p *agentv1.LogCollectionPolicy
	if !req.Msg.Inherit {
		if err := validatePolicy(req.Msg.Policy); err != nil {
			return nil, err
		}
		p = req.Msg.Policy
	}
	if err := l.s.Nodes.SetLogPolicy(ctx, req.Msg.NodeId, p); err != nil {
		return nil, toConnectError(err)
	}
	detail := "inherit"
	if p != nil {
		detail = p.String()
	}
	l.s.audit(ctx, "logs.policy", req.Msg.NodeId, detail)
	return connect.NewResponse(&apiv1.SetNodeCollectionPolicyResponse{}), nil
}

func retentionProto(r logs.Retention) *apiv1.RetentionPolicy {
	rot := apiv1.RotateInterval_ROTATE_INTERVAL_HOURLY
	if r.Daily {
		rot = apiv1.RotateInterval_ROTATE_INTERVAL_DAILY
	}
	return &apiv1.RetentionPolicy{
		Rotate: rot, MaxSegmentBytes: uint64(r.MaxSegmentBytes), MaxAgeHours: uint32(r.MaxAge / time.Hour),
		MaxBytesPerNode: uint64(r.MaxBytesPerNode), MaxTotalBytes: uint64(r.MaxTotalBytes), Compress: r.Compress,
	}
}

func (l *logService) GetRetentionPolicy(ctx context.Context, _ *connect.Request[apiv1.GetRetentionPolicyRequest]) (*connect.Response[apiv1.GetRetentionPolicyResponse], error) {
	r, err := l.s.Logs.Retention(ctx)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.GetRetentionPolicyResponse{Policy: retentionProto(r)}), nil
}

func (l *logService) SetRetentionPolicy(ctx context.Context, req *connect.Request[apiv1.SetRetentionPolicyRequest]) (*connect.Response[apiv1.SetRetentionPolicyResponse], error) {
	p := req.Msg.Policy
	if p == nil {
		return nil, invalid("policy is required")
	}
	r := logs.Retention{
		Daily: p.Rotate == apiv1.RotateInterval_ROTATE_INTERVAL_DAILY, MaxSegmentBytes: int64(p.MaxSegmentBytes),
		MaxAge: time.Duration(p.MaxAgeHours) * time.Hour, MaxBytesPerNode: int64(p.MaxBytesPerNode),
		MaxTotalBytes: int64(p.MaxTotalBytes), Compress: p.Compress,
	}
	if err := l.s.Logs.SetRetention(ctx, r); err != nil {
		return nil, toConnectError(err)
	}
	l.s.audit(ctx, "logs.retention", "global", p.String())
	return connect.NewResponse(&apiv1.SetRetentionPolicyResponse{Policy: retentionProto(r)}), nil
}

func (l *logService) ListLogFiles(_ context.Context, req *connect.Request[apiv1.ListLogFilesRequest]) (*connect.Response[apiv1.ListLogFilesResponse], error) {
	fs := l.s.Logs.Files()
	if fs == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("logs are stored in a custom sink"))
	}
	files, err := fs.List(req.Msg.NodeId, req.Msg.Type)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	resp := &apiv1.ListLogFilesResponse{}
	for _, f := range files {
		resp.Files = append(resp.Files, &apiv1.LogFile{NodeId: f.NodeID, Type: f.Type, Path: f.Path, Size: uint64(f.Size), ModTime: ts(f.ModTime), Compressed: f.Compressed})
		resp.TotalBytes += uint64(f.Size)
	}
	return connect.NewResponse(resp), nil
}

func (l *logService) TailLog(ctx context.Context, req *connect.Request[apiv1.TailLogRequest], stream *connect.ServerStream[apiv1.TailLogResponse]) error {
	fs := l.s.Logs.Files()
	if fs == nil {
		return connect.NewError(connect.CodeUnimplemented, errors.New("logs are stored in a custom sink"))
	}
	if !logTypeValid(req.Msg.Type) {
		return invalid("type is required")
	}
	if req.Msg.NodeId == "" {
		return invalid("node_id is required")
	}
	n := int(req.Msg.Lines)
	if n <= 0 || n > 5000 {
		n = 200
	}
	var follow <-chan [][]byte
	if req.Msg.Follow {
		// Subscribe before reading history so no record is missed.
		follow = l.s.Logs.Follow(ctx, req.Msg.NodeId, req.Msg.Type)
	}
	lines, err := fs.TailLines(req.Msg.NodeId, req.Msg.Type, n, req.Msg.Filter)
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := stream.Send(&apiv1.TailLogResponse{Lines: lines}); err != nil {
		return err
	}
	if follow == nil {
		return nil
	}
	for recs := range follow {
		var out []string
		for _, r := range recs {
			if req.Msg.Filter == "" || strings.Contains(string(r), req.Msg.Filter) {
				out = append(out, string(r))
			}
		}
		if len(out) == 0 {
			continue
		}
		if err := stream.Send(&apiv1.TailLogResponse{Lines: out}); err != nil {
			return err
		}
	}
	return nil
}

func (l *logService) GetIngestStats(context.Context, *connect.Request[apiv1.GetIngestStatsRequest]) (*connect.Response[apiv1.GetIngestStatsResponse], error) {
	st := l.s.Logs.Stats()
	resp := &apiv1.GetIngestStatsResponse{
		QueueBytes: uint64(st.Queue.Bytes), QueueCapacityBytes: uint64(st.Queue.Capacity),
		QueueDroppedRecords: st.Queue.Dropped, WrittenRecords: st.Written,
	}
	for id, n := range st.Nodes {
		resp.Nodes = append(resp.Nodes, &apiv1.NodeIngestStats{NodeId: id, Records: n.Records, Bytes: n.Bytes, AgentDropped: n.AgentDropped})
	}
	return connect.NewResponse(resp), nil
}

// downloadLog serves GET /logs/download?node=<id>&path=<type>/<file>,
// decompressing .zst segments.
func (s *Server) downloadLog(w http.ResponseWriter, r *http.Request) {
	node, p := r.URL.Query().Get("node"), r.URL.Query().Get("path")
	rc, err := s.Logs.OpenFile(node, p)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer rc.Close()
	name := strings.TrimSuffix(path.Base(p), ".zst")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", node+"-"+name))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.Copy(w, rc)
}
