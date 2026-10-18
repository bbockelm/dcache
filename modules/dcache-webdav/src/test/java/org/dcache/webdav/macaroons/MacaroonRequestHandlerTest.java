/* dCache - http://www.dcache.org/
 *
 * Copyright (C) 2026 Deutsches Elektronen-Synchrotron
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.dcache.webdav.macaroons;

import static javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static javax.servlet.http.HttpServletResponse.SC_FORBIDDEN;
import static org.dcache.auth.attributes.Activity.DELETE;
import static org.dcache.auth.attributes.Activity.DOWNLOAD;
import static org.dcache.auth.attributes.Activity.LIST;
import static org.dcache.auth.attributes.Activity.MANAGE;
import static org.dcache.auth.attributes.Activity.READ_METADATA;
import static org.dcache.auth.attributes.Activity.UPDATE_METADATA;
import static org.dcache.auth.attributes.Activity.UPLOAD;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import diskCacheV111.util.FsPath;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import org.dcache.auth.GidPrincipal;
import org.dcache.auth.UidPrincipal;
import org.dcache.auth.UserNamePrincipal;
import org.dcache.auth.attributes.Activity;
import org.dcache.auth.attributes.DenyActivityRestriction;
import org.dcache.auth.attributes.LoginAttribute;
import org.dcache.auth.attributes.MultiTargetedRestriction;
import org.dcache.auth.attributes.MultiTargetedRestriction.Authorisation;
import org.dcache.auth.attributes.PrefixRestriction;
import org.dcache.auth.attributes.Restriction;
import org.dcache.auth.attributes.RootDirectory;
import org.dcache.http.AuthenticationHandler;
import org.dcache.http.PathMapper;
import org.dcache.macaroons.MacaroonContext;
import org.junit.Before;
import org.junit.Test;

public class MacaroonRequestHandlerTest {

    /* The activities of the WLCG profile's storage.read, storage.create and
     * storage.modify scopes.
     */
    private static final EnumSet<Activity> READ = EnumSet.of(LIST, READ_METADATA, DOWNLOAD);
    private static final EnumSet<Activity> CREATE = EnumSet.of(READ_METADATA, UPLOAD, MANAGE,
          UPDATE_METADATA);
    private static final EnumSet<Activity> MODIFY = EnumSet.of(LIST, READ_METADATA, UPLOAD,
          MANAGE, DELETE, UPDATE_METADATA);

    private static final Subject SUBJECT = new Subject(false,
          Set.of(new UidPrincipal(1000), new GidPrincipal(1000, true),
                new UserNamePrincipal("pelican")), Set.of(), Set.of());

    private MacaroonRequestHandler handler;
    private Set<LoginAttribute> loginAttributes;
    private HttpServletRequest request;

    @Before
    public void setup() {
        handler = new MacaroonRequestHandler();
        handler.setPathMapper(new PathMapper());
        loginAttributes = new HashSet<>();
        request = mock(HttpServletRequest.class);
        given(request.getAttribute(AuthenticationHandler.DCACHE_LOGIN_ATTRIBUTES))
              .willReturn(loginAttributes);
    }

    @Test
    public void shouldLimitMacaroonForUnrestrictedUserOnlyByPath() throws Exception {
        MacaroonContext context = buildContext("/data/pelican");

        assertThat(context.getPath(), is(Optional.of("/data/pelican")));
        assertThat(context.getAllowedActivities(), is(Optional.empty()));
    }

    @Test
    public void shouldIssueMacaroonForTokenAuthorisingRequestedPath() throws Exception {
        givenToken(new Authorisation(READ, FsPath.create("/data/pelican")));

        MacaroonContext context = buildContext("/data/pelican");

        assertThat(context.getRoot(), is(Optional.empty()));
        assertThat(context.getPath(), is(Optional.of("/data/pelican")));
        assertThat(context.getAllowedActivities(), is(Optional.of(READ)));
    }

    @Test
    public void shouldIssueMacaroonForPathBelowTokenAuthorisation() throws Exception {
        givenToken(new Authorisation(READ, FsPath.create("/data/pelican")));

        MacaroonContext context = buildContext("/data/pelican/sub");

        assertThat(context.getPath(), is(Optional.of("/data/pelican/sub")));
        assertThat(context.getAllowedActivities(), is(Optional.of(READ)));
    }

    @Test
    public void shouldUnionActivitiesOfAllAuthorisationsOfParentPaths() throws Exception {
        givenToken(new Authorisation(READ, FsPath.create("/data")),
              new Authorisation(CREATE, FsPath.create("/data/pelican")));

        MacaroonContext context = buildContext("/data/pelican/sub");

        EnumSet<Activity> expected = EnumSet.copyOf(READ);
        expected.addAll(CREATE);
        assertThat(context.getPath(), is(Optional.of("/data/pelican/sub")));
        assertThat(context.getAllowedActivities(), is(Optional.of(expected)));
    }

    @Test
    public void shouldIgnoreAuthorisationsBelowRequestedPath() throws Exception {
        givenToken(new Authorisation(READ, FsPath.create("/data/pelican")),
              new Authorisation(MODIFY, FsPath.create("/data/pelican/sub")));

        MacaroonContext context = buildContext("/data/pelican");

        assertThat(context.getPath(), is(Optional.of("/data/pelican")));
        assertThat(context.getAllowedActivities(), is(Optional.of(READ)));
    }

    @Test
    public void shouldIgnoreAuthorisationsOfSiblingWithCommonPrefix() throws Exception {
        givenToken(new Authorisation(READ, FsPath.create("/data/pelican")),
              new Authorisation(MODIFY, FsPath.create("/data/pel")));

        MacaroonContext context = buildContext("/data/pelican");

        assertThat(context.getAllowedActivities(), is(Optional.of(READ)));
    }

    @Test
    public void shouldRefuseWhenNoAuthorisationCoversRequestedPath() {
        givenToken(new Authorisation(MODIFY, FsPath.create("/data/other")));

        assertRefused("/data/pelican", SC_FORBIDDEN, "no activity");
    }

    @Test
    public void shouldRefuseWhenOnlyAuthorisationsBelowRequestedPath() {
        givenToken(new Authorisation(READ, FsPath.create("/data/pelican/sub")));

        assertRefused("/data/pelican", SC_FORBIDDEN, "no activity");
    }

    @Test
    public void shouldUseOnlyRootAuthorisationsForRootTarget() throws Exception {
        givenToken(new Authorisation(READ, FsPath.ROOT),
              new Authorisation(MODIFY, FsPath.create("/data")));

        MacaroonContext context = buildContext("/");

        assertThat(context.getPath(), is(Optional.empty()));
        assertThat(context.getAllowedActivities(), is(Optional.of(READ)));
    }

    @Test
    public void shouldRefuseRootTargetWithoutRootAuthorisation() {
        givenToken(new Authorisation(READ, FsPath.create("/data")));

        assertRefused("/", SC_FORBIDDEN, "no activity");
    }

    @Test
    public void shouldRefuseAuthorisationWithoutReadMetadata() {
        givenToken(new Authorisation(EnumSet.of(DOWNLOAD), FsPath.create("/data")));

        assertRefused("/data", SC_BAD_REQUEST, "READ_METADATA");
    }

    @Test
    public void shouldNarrowPrefixRestrictionToRequestedPath() throws Exception {
        loginAttributes.add(new PrefixRestriction(FsPath.create("/data")));
        givenToken(new Authorisation(READ, FsPath.create("/data/pelican")));

        MacaroonContext context = buildContext("/data/pelican/sub");

        assertThat(context.getPath(), is(Optional.of("/data/pelican/sub")));
        assertThat(context.getAllowedActivities(), is(Optional.of(READ)));
    }

    @Test
    public void shouldRefusePathOutsidePrefixRestriction() {
        loginAttributes.add(new PrefixRestriction(FsPath.create("/data/other")));
        givenToken(new Authorisation(READ, FsPath.create("/data")));

        assertRefused("/data/pelican", SC_BAD_REQUEST, "not within existing path");
    }

    @Test
    public void shouldUseAuthorisationsForPrefixRestrictionWithRootTarget() throws Exception {
        loginAttributes.add(new PrefixRestriction(FsPath.create("/data/pelican")));
        givenToken(new Authorisation(READ, FsPath.create("/data")));

        MacaroonContext context = buildContext("/");

        assertThat(context.getPath(), is(Optional.of("/data/pelican")));
        assertThat(context.getAllowedActivities(), is(Optional.of(READ)));
    }

    @Test
    public void shouldResolveRequestedPathAgainstUserRoot() throws Exception {
        loginAttributes.add(new RootDirectory("/data"));
        givenToken(new Authorisation(READ, FsPath.create("/data/pelican")),
              new Authorisation(MODIFY, FsPath.create("/data/other")));

        MacaroonContext context = buildContext("/pelican");

        assertThat(context.getRoot(), is(Optional.of(FsPath.create("/data"))));
        assertThat(context.getPath(), is(Optional.of("/pelican")));
        assertThat(context.getAllowedActivities(), is(Optional.of(READ)));
    }

    @Test
    public void shouldUseAuthorisationsOfUserRootForRootTarget() throws Exception {
        loginAttributes.add(new RootDirectory("/data/pelican"));
        givenToken(new Authorisation(READ, FsPath.create("/data")));

        MacaroonContext context = buildContext("/");

        assertThat(context.getRoot(), is(Optional.of(FsPath.create("/data/pelican"))));
        assertThat(context.getPath(), is(Optional.empty()));
        assertThat(context.getAllowedActivities(), is(Optional.of(READ)));
    }

    @Test
    public void shouldKeepActivitiesDeniedElsewhereInLogin() throws Exception {
        loginAttributes.add(new DenyActivityRestriction(DOWNLOAD));
        givenToken(new Authorisation(READ, FsPath.create("/data/pelican")));

        MacaroonContext context = buildContext("/data/pelican");

        assertThat(context.getAllowedActivities(),
              is(Optional.of(EnumSet.of(LIST, READ_METADATA))));
    }

    @Test
    public void shouldIntersectMultipleMultiTargetedRestrictions() throws Exception {
        givenToken(new Authorisation(MODIFY, FsPath.create("/data")));
        givenToken(new Authorisation(READ, FsPath.create("/data/pelican")));

        MacaroonContext context = buildContext("/data/pelican");

        assertThat(context.getAllowedActivities(),
              is(Optional.of(EnumSet.of(LIST, READ_METADATA))));
    }

    /**
     * Check, for a set of tokens, user roots and requested paths, that whatever the macaroon
     * allows the token allows too.  The macaroon's restrictions are derived from the
     * MacaroonContext in the same way as MacaroonLoginStrategy does it.
     */
    @Test
    public void shouldNeverAllowMoreThanToken() throws Exception {
        List<FsPath> paths = paths("/", "/data", "/data/pelican", "/data/pelican/sub",
              "/data/pelican/sub/file", "/data/pelican/file", "/data/pel", "/data/other",
              "/data/other/file", "/other");
        List<List<Authorisation>> tokens = List.of(
              List.of(new Authorisation(READ, FsPath.create("/data/pelican"))),
              List.of(new Authorisation(MODIFY, FsPath.create("/data/pelican/sub"))),
              List.of(new Authorisation(READ, FsPath.create("/data")),
                    new Authorisation(CREATE, FsPath.create("/data/pelican"))),
              List.of(new Authorisation(READ, FsPath.create("/data/pelican")),
                    new Authorisation(MODIFY, FsPath.create("/data/pelican/sub")),
                    new Authorisation(CREATE, FsPath.create("/data/other"))),
              List.of(new Authorisation(EnumSet.of(READ_METADATA), FsPath.create("/data")),
                    new Authorisation(READ, FsPath.create("/data/pelican/sub"))),
              List.of(new Authorisation(READ, FsPath.ROOT),
                    new Authorisation(MODIFY, FsPath.create("/data/pelican"))));
        List<FsPath> userRoots = paths("/", "/data");

        int issued = 0;
        for (List<Authorisation> token : tokens) {
            for (FsPath userRoot : userRoots) {
                for (FsPath desired : paths) {
                    if (!desired.hasPrefix(userRoot)) {
                        continue;
                    }
                    setup();
                    loginAttributes.add(new RootDirectory(userRoot));
                    MultiTargetedRestriction tokenRestriction =
                          new MultiTargetedRestriction(token);
                    loginAttributes.add(tokenRestriction);

                    MacaroonContext context;
                    try {
                        context = buildContext(desired.stripPrefix(userRoot));
                    } catch (ErrorResponseException e) {
                        continue;
                    }
                    issued++;

                    FsPath macaroonRoot = context.getRoot().orElse(FsPath.ROOT);
                    List<Restriction> macaroon = new ArrayList<>();
                    context.getPath().map(macaroonRoot::chroot).map(PrefixRestriction::new)
                          .ifPresent(macaroon::add);
                    context.getAllowedActivities().map(EnumSet::complementOf)
                          .map(DenyActivityRestriction::new).ifPresent(macaroon::add);

                    for (FsPath path : paths) {
                        for (Activity activity : Activity.values()) {
                            boolean macaroonAllows = path.hasPrefix(macaroonRoot)
                                  && macaroon.stream()
                                  .noneMatch(r -> r.isRestricted(activity, path));
                            boolean tokenAllows = path.hasPrefix(userRoot)
                                  && !tokenRestriction.isRestricted(activity, path);
                            assertThat("Token " + token + ", root " + userRoot + ", macaroon for "
                                        + desired + ": " + activity + " on " + path,
                                  !macaroonAllows || tokenAllows, is(true));
                        }
                    }
                }
            }
        }
        assertThat(issued, greaterThan(0));
    }

    private void givenToken(Authorisation... authorisations) {
        loginAttributes.add(new MultiTargetedRestriction(Arrays.asList(authorisations)));
    }

    private MacaroonContext buildContext(String target) throws ErrorResponseException {
        return handler.buildContext(target, request, SUBJECT);
    }

    private void assertRefused(String target, int status, String reason) {
        ErrorResponseException e = assertThrows(ErrorResponseException.class,
              () -> buildContext(target));
        assertThat(e.getStatus(), equalTo(status));
        assertThat(e.getMessage(), containsString(reason));
    }

    private static List<FsPath> paths(String... paths) {
        return Arrays.stream(paths).map(FsPath::create).toList();
    }
}
