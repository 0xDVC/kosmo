# kosmo
yet another deployment tool. my vision is a self-hosted tool with no vendor lockin. absolute ownership of your infra. i love some existent solutions.

but this is a rabbit-hole project. a frying pan to fire situation.

## issues
-- automated bare repo creation doesn't work by just using git
i designed it to a be a push from client to server approach with git to start with.
was trying to iterate to automate repo creation on server and then a git push from client would then push code to server.
interestingly, git can't execute shell script with its hooks for custom actions like auto create bare repo. it can only do that after a git repo is initialized. hooks only work once a repo exists.
so i can't auto-create a repo out of nothing with a hook. creating a repo just to auto create repos would introduce overheads with branch management for each app that is deployed, might work for single apps. not sure multi apps would work.
maybe explore later??
    
    -- solution??


